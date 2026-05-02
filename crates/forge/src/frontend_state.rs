//! Frontend state virtual-edge extraction for IFDS taint propagation.
//!
//! React context, Redux reducers, and WebSocket callbacks hide data movement
//! behind framework dispatch mechanisms that do not appear as ordinary function
//! calls. This module emits bounded synthetic call-graph edges so downstream
//! IFDS consumers can reattach taint after those framework transitions.

use std::collections::{BTreeMap, BTreeSet};

use std::collections::HashMap;

use petgraph::graph::NodeIndex;
use smallvec::{smallvec, SmallVec};

use crate::callgraph::{CallGraph, CallSiteArgs, EdgeKind};
use crate::ifds::{CallBinding, CallSite, FunctionModel, TaintLabel};

const MAX_FRONTEND_STATE_BYTES: usize = 512 * 1024;

/// Framework bridge encoded as a virtual call-graph edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VirtualEdgeKind {
    /// React `<Context.Provider value={x}>` to `useContext(Context)`.
    ReactContextProvider,
    /// Redux `dispatch({ type, payload })` to matching reducer case.
    ReduxDispatchReducer,
    /// WebSocket / event-emitter `.on(event, handler)` registration.
    WebSocketHandler,
}

/// Synthetic dataflow edge recovered from frontend framework state plumbing.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VirtualEdge {
    /// Source function or module scope where the state transition is initiated.
    pub from: String,
    /// Destination function that observes the state transition.
    pub to: String,
    /// Stable taint binding label carried across the virtual edge.
    pub binding: String,
    /// Framework bridge kind.
    pub kind: VirtualEdgeKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FunctionSpan {
    name: String,
    start: usize,
    end: usize,
}

/// Build synthetic frontend state edges from `source`.
///
/// The extraction is deterministic and bounded to 512 KiB per file. It models:
/// React `Provider` / `useContext`, Redux `dispatch(action)` / reducer cases,
/// and WebSocket `.on(event, handler)` callbacks. Redux payload bindings are
/// preserved in the edge label so a tainted dispatch payload can re-emerge in
/// the reducer state fact set.
pub fn build_frontend_state_edges(_call_graph: &CallGraph, source: &[u8]) -> Vec<VirtualEdge> {
    if source.len() > MAX_FRONTEND_STATE_BYTES {
        return Vec::new();
    }
    let Ok(text) = std::str::from_utf8(source) else {
        return Vec::new();
    };

    let functions = collect_function_spans(text);
    let mut edges = Vec::new();
    edges.extend(react_context_edges(text, &functions));
    edges.extend(redux_edges(text, &functions));
    edges.extend(websocket_edges(text, &functions));

    let mut deduped = BTreeSet::new();
    for edge in edges {
        deduped.insert(edge);
    }
    deduped.into_iter().collect()
}

/// Attach frontend virtual edges to the IFDS call graph and function models.
///
/// Redux edges translate `payload` arguments from caller parameter labels into
/// reducer-state labels (`redux_state:<TYPE>:payload`), which makes taint
/// reappear in the reducer even though the runtime transition is driven by the
/// Redux store rather than a direct function call.
pub fn apply_frontend_state_edges(
    graph: &mut CallGraph,
    models: &mut HashMap<String, FunctionModel>,
    edges: &[VirtualEdge],
) {
    for edge in edges {
        let from = ensure_node(graph, &edge.from);
        let to = ensure_node(graph, &edge.to);
        let call_site_args = CallSiteArgs {
            args: Vec::new(),
            kind: EdgeKind::Call,
        };
        if let Some(edge_id) = graph.find_edge(from, to) {
            if let Some(weight) = graph.edge_weight_mut(edge_id) {
                weight.push(call_site_args);
            }
        } else {
            graph.add_edge(from, to, smallvec![call_site_args]);
        }

        let Some(binding) = ifds_binding_for_edge(edge) else {
            continue;
        };
        models
            .entry(edge.from.clone())
            .or_default()
            .calls
            .push(CallSite {
                callee: edge.to.clone(),
                bindings: SmallVec::from_vec(vec![binding]),
            });
        models.entry(edge.to.clone()).or_default();
    }
}

fn ensure_node(graph: &mut CallGraph, name: &str) -> NodeIndex {
    if let Some(index) = graph.node_indices().find(|index| graph[*index] == name) {
        index
    } else {
        graph.add_node(name.to_string())
    }
}

fn ifds_binding_for_edge(edge: &VirtualEdge) -> Option<CallBinding> {
    match edge.kind {
        VirtualEdgeKind::ReduxDispatchReducer => {
            let action = edge
                .binding
                .strip_prefix("ReduxAction:")?
                .split_once(":payload:")?
                .0;
            let payload = edge.binding.rsplit_once(":payload:")?.1;
            Some(CallBinding {
                caller_label: TaintLabel::new(format!("param:{payload}")),
                callee_label: TaintLabel::new(format!("redux_state:{action}:payload")),
            })
        }
        VirtualEdgeKind::ReactContextProvider => {
            let context = edge
                .binding
                .strip_prefix("ReactContext:")?
                .split_once(":value:")?
                .0;
            let value = edge.binding.rsplit_once(":value:")?.1;
            Some(CallBinding {
                caller_label: TaintLabel::new(format!("param:{value}")),
                callee_label: TaintLabel::new(format!("react_context:{context}:value")),
            })
        }
        VirtualEdgeKind::WebSocketHandler => {
            let event = edge
                .binding
                .strip_prefix("WebSocketEvent:")?
                .split_once(":handler:")?
                .0;
            Some(CallBinding {
                caller_label: TaintLabel::new(format!("websocket_event:{event}")),
                callee_label: TaintLabel::new(format!("websocket_event:{event}")),
            })
        }
    }
}

fn collect_function_spans(text: &str) -> Vec<FunctionSpan> {
    let mut starts: Vec<(String, usize)> = Vec::new();
    let mut offset = 0usize;
    for line in text.lines() {
        if let Some(name) = extract_function_name(line.trim_start()) {
            starts.push((name.to_string(), offset));
        }
        offset = offset.saturating_add(line.len()).saturating_add(1);
    }

    starts.sort_by_key(|(_, start)| *start);
    let mut spans = Vec::with_capacity(starts.len());
    for index in 0..starts.len() {
        let (name, start) = &starts[index];
        let end = starts
            .get(index + 1)
            .map(|(_, next_start)| *next_start)
            .unwrap_or(text.len());
        spans.push(FunctionSpan {
            name: name.clone(),
            start: *start,
            end,
        });
    }
    spans
}

fn extract_function_name(line: &str) -> Option<&str> {
    for prefix in [
        "export async function ",
        "async function ",
        "export function ",
        "function ",
    ] {
        if let Some(rest) = line.strip_prefix(prefix) {
            return take_identifier(rest.trim_start());
        }
    }

    for prefix in ["export const ", "export let ", "const ", "let ", "var "] {
        let Some(rest) = line.strip_prefix(prefix) else {
            continue;
        };
        let rest = rest.trim_start();
        let name = take_identifier(rest)?;
        let after = rest[name.len()..].trim_start();
        if after.starts_with('=') && (after.contains("=>") || after.contains("function")) {
            return Some(name);
        }
    }

    None
}

fn enclosing_function(functions: &[FunctionSpan], offset: usize) -> String {
    functions
        .iter()
        .find(|function| offset >= function.start && offset < function.end)
        .map(|function| function.name.clone())
        .unwrap_or_else(|| "module".to_string())
}

fn function_named<'a>(functions: &'a [FunctionSpan], name: &str) -> Option<&'a FunctionSpan> {
    functions.iter().find(|function| function.name == name)
}

fn react_context_edges(text: &str, functions: &[FunctionSpan]) -> Vec<VirtualEdge> {
    let contexts = collect_contexts(text);
    let mut edges = Vec::new();
    for context in contexts {
        let provider_pattern = format!("<{context}.Provider");
        let consumer_pattern = format!("useContext({context}");
        let mut providers = Vec::new();
        for provider_offset in find_offsets(text, &provider_pattern) {
            let window = bounded_window(text, provider_offset, 512);
            let value = extract_jsx_value(window, "value").unwrap_or_else(|| "value".to_string());
            providers.push((
                provider_offset,
                enclosing_function(functions, provider_offset),
                value,
            ));
        }
        if providers.is_empty() {
            continue;
        }
        for consumer_offset in find_offsets(text, &consumer_pattern) {
            let consumer = enclosing_function(functions, consumer_offset);
            for (_, provider, value) in &providers {
                edges.push(VirtualEdge {
                    from: provider.clone(),
                    to: consumer.clone(),
                    binding: format!("ReactContext:{context}:value:{value}"),
                    kind: VirtualEdgeKind::ReactContextProvider,
                });
            }
        }
    }
    edges
}

fn redux_edges(text: &str, functions: &[FunctionSpan]) -> Vec<VirtualEdge> {
    let mut reducer_cases: BTreeMap<String, String> = BTreeMap::new();
    for function in functions {
        let body = text.get(function.start..function.end).unwrap_or("");
        if !function.name.to_ascii_lowercase().contains("reducer")
            && !body.contains("action.type")
            && !body.contains("addCase(")
        {
            continue;
        }
        for action_type in collect_reducer_action_types(body) {
            reducer_cases.insert(action_type, function.name.clone());
        }
    }

    let mut edges = Vec::new();
    for dispatch_offset in find_offsets(text, "dispatch(") {
        let window = bounded_window(text, dispatch_offset, 768);
        let Some(action_type) = extract_action_type(window) else {
            continue;
        };
        let Some(reducer) = reducer_cases.get(&action_type) else {
            continue;
        };
        let payload = extract_payload_identifier(window).unwrap_or_else(|| "payload".to_string());
        edges.push(VirtualEdge {
            from: enclosing_function(functions, dispatch_offset),
            to: reducer.clone(),
            binding: format!("ReduxAction:{action_type}:payload:{payload}"),
            kind: VirtualEdgeKind::ReduxDispatchReducer,
        });
    }
    edges
}

fn websocket_edges(text: &str, functions: &[FunctionSpan]) -> Vec<VirtualEdge> {
    let mut edges = Vec::new();
    for pattern in [".on(", ".addEventListener("] {
        for offset in find_offsets(text, pattern) {
            let window = bounded_window(text, offset, 512);
            let Some((event, handler)) = extract_event_handler(window) else {
                continue;
            };
            if function_named(functions, &handler).is_none() {
                continue;
            }
            edges.push(VirtualEdge {
                from: enclosing_function(functions, offset),
                to: handler.clone(),
                binding: format!("WebSocketEvent:{event}:handler:{handler}"),
                kind: VirtualEdgeKind::WebSocketHandler,
            });
        }
    }
    edges
}

fn collect_contexts(text: &str) -> Vec<String> {
    let mut contexts = BTreeSet::new();
    for line in text.lines() {
        if !line.contains("createContext") {
            continue;
        }
        if let Some(name) = assigned_identifier(line) {
            contexts.insert(name.to_string());
        }
    }
    contexts.into_iter().collect()
}

fn assigned_identifier(line: &str) -> Option<&str> {
    let before_equals = line.split_once('=')?.0.trim();
    before_equals
        .split_whitespace()
        .rev()
        .find_map(take_identifier)
}

fn collect_reducer_action_types(body: &str) -> Vec<String> {
    let mut types = BTreeSet::new();
    for pattern in ["case '", "case \"", "addCase('", "addCase(\""] {
        let quote = if pattern.ends_with('\'') { '\'' } else { '"' };
        let mut search_at = 0usize;
        while let Some(relative) = body[search_at..].find(pattern) {
            let start = search_at + relative + pattern.len();
            let Some(end_relative) = body[start..].find(quote) else {
                break;
            };
            let action_type = &body[start..start + end_relative];
            if !action_type.trim().is_empty() {
                types.insert(action_type.to_string());
            }
            search_at = start + end_relative + 1;
        }
    }
    types.into_iter().collect()
}

fn extract_action_type(window: &str) -> Option<String> {
    let type_pos = window.find("type")?;
    let after = &window[type_pos + "type".len()..];
    let quote_pos = after.find(['\'', '"'])?;
    let quote = after.as_bytes().get(quote_pos).copied()? as char;
    let value_start = quote_pos + 1;
    let value_end = after[value_start..].find(quote)?;
    Some(after[value_start..value_start + value_end].to_string())
}

fn extract_payload_identifier(window: &str) -> Option<String> {
    let payload_pos = window.find("payload")?;
    let after = &window[payload_pos + "payload".len()..];
    let value_start = after.find(':')? + 1;
    let value = after[value_start..].trim_start();
    let end = value
        .char_indices()
        .find_map(|(index, ch)| {
            if index == 0 {
                None
            } else if !(ch == '_' || ch == '$' || ch == '.' || ch.is_ascii_alphanumeric()) {
                Some(index)
            } else {
                None
            }
        })
        .unwrap_or(value.len());
    let candidate = value[..end].trim();
    if candidate.is_empty() {
        None
    } else {
        Some(candidate.to_string())
    }
}

fn extract_event_handler(window: &str) -> Option<(String, String)> {
    let open = window.find('(')?;
    let args = &window[open + 1..];
    let event = extract_first_string(args)?;
    let comma = args.find(',')?;
    let after_comma = args[comma + 1..].trim_start();
    let handler = take_identifier(after_comma)?;
    Some((event, handler.to_string()))
}

fn extract_first_string(input: &str) -> Option<String> {
    let start = input.find(['\'', '"'])?;
    let quote = input.as_bytes().get(start).copied()? as char;
    let value_start = start + 1;
    let value_end = input[value_start..].find(quote)?;
    Some(input[value_start..value_start + value_end].to_string())
}

fn extract_jsx_value(window: &str, attr: &str) -> Option<String> {
    let attr_pos = window.find(attr)?;
    let after = window[attr_pos + attr.len()..].trim_start();
    let after = after.strip_prefix('=')?.trim_start();
    if let Some(rest) = after.strip_prefix('{') {
        let end = rest.find('}')?;
        let value = rest[..end].trim();
        return if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        };
    }
    extract_first_string(after)
}

fn find_offsets(text: &str, pattern: &str) -> Vec<usize> {
    let mut offsets = Vec::new();
    let mut search_at = 0usize;
    while let Some(relative) = text[search_at..].find(pattern) {
        let offset = search_at + relative;
        offsets.push(offset);
        search_at = offset.saturating_add(pattern.len());
    }
    offsets
}

fn bounded_window(text: &str, offset: usize, len: usize) -> &str {
    let end = text.len().min(offset.saturating_add(len));
    text.get(offset..end).unwrap_or("")
}

fn take_identifier(input: &str) -> Option<&str> {
    let mut end = 0usize;
    for (index, ch) in input.char_indices() {
        let valid = if index == 0 {
            ch == '_' || ch == '$' || ch.is_ascii_alphabetic()
        } else {
            ch == '_' || ch == '$' || ch.is_ascii_alphanumeric()
        };
        if !valid {
            break;
        }
        end = index + ch.len_utf8();
    }
    if end == 0 {
        None
    } else {
        Some(&input[..end])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redux_dispatch_payload_reemerges_in_reducer_edge() {
        let source = br#"
function publish(channelName) {
  dispatch({ type: 'CHANNEL_RECEIVED', payload: channelName });
}

function channelsReducer(state, action) {
  switch (action.type) {
    case 'CHANNEL_RECEIVED':
      return { ...state, name: action.payload };
    default:
      return state;
  }
}
"#;
        let graph = crate::callgraph::build_call_graph("tsx", source);

        let edges = build_frontend_state_edges(&graph, source);

        assert!(edges.iter().any(|edge| {
            edge.kind == VirtualEdgeKind::ReduxDispatchReducer
                && edge.from == "publish"
                && edge.to == "channelsReducer"
                && edge.binding.contains("CHANNEL_RECEIVED")
                && edge.binding.contains("channelName")
        }));
    }

    #[test]
    fn react_context_provider_links_to_consumer() {
        let source = br#"
const AuthContext = createContext(null);

function AuthProvider({ token, children }) {
  return <AuthContext.Provider value={token}>{children}</AuthContext.Provider>;
}

function UseAuth() {
  return useContext(AuthContext);
}
"#;
        let graph = crate::callgraph::build_call_graph("tsx", source);

        let edges = build_frontend_state_edges(&graph, source);

        assert!(edges.iter().any(|edge| {
            edge.kind == VirtualEdgeKind::ReactContextProvider
                && edge.from == "AuthProvider"
                && edge.to == "UseAuth"
                && edge.binding.contains("token")
        }));
    }

    #[test]
    fn websocket_binding_edges_to_registered_handler() {
        let source = br#"
function configure(socket) {
  socket.on('message', handleMessage);
}

function handleMessage(frame) {
  return frame.data;
}
"#;
        let graph = crate::callgraph::build_call_graph("tsx", source);

        let edges = build_frontend_state_edges(&graph, source);

        assert!(edges.iter().any(|edge| {
            edge.kind == VirtualEdgeKind::WebSocketHandler
                && edge.from == "configure"
                && edge.to == "handleMessage"
                && edge.binding.contains("message")
        }));
    }

    #[test]
    fn redux_virtual_edge_propagates_payload_through_ifds_solver() {
        let source = br#"
function publish(channelName) {
  dispatch({ type: 'CHANNEL_RECEIVED', payload: channelName });
}

function channelsReducer(state, action) {
  switch (action.type) {
    case 'CHANNEL_RECEIVED':
      return { ...state, name: action.payload };
    default:
      return state;
  }
}
"#;
        let mut graph = crate::callgraph::build_call_graph("tsx", source);
        let edges = build_frontend_state_edges(&graph, source);
        let mut models = HashMap::new();
        models.insert(
            "channelsReducer".to_string(),
            FunctionModel {
                sinks: SmallVec::from_vec(vec![crate::ifds::SinkBinding {
                    label: TaintLabel::new("redux_state:CHANNEL_RECEIVED:payload"),
                    sink_label: "sink:redux_state:update".to_string(),
                }]),
                ..FunctionModel::default()
            },
        );

        apply_frontend_state_edges(&mut graph, &mut models, &edges);
        let mut solver = crate::ifds::IfdsSolver::new(graph, models);
        let result = solver.solve(&[crate::ifds::InputFact {
            function: "publish".to_string(),
            label: TaintLabel::new("param:channelName"),
        }]);

        assert!(result.witnesses.iter().any(|witness| {
            witness.sink_label == "sink:redux_state:update"
                && witness.call_chain == vec!["publish".to_string(), "channelsReducer".to_string()]
        }));
    }
}
