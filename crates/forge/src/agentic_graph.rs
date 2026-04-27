//! Agentic framework execution graph extraction.
//!
//! This module performs a bounded byte/text scan for LangChain, AutoGen, and
//! CrewAI call graphs where untrusted prompt input reaches privileged local
//! tools without a visible sandbox boundary.

use common::slop::StructuredFinding;

/// Supported agentic framework marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AgenticFramework {
    /// LangChain Python or TypeScript APIs.
    LangChain,
    /// Microsoft AutoGen APIs.
    AutoGen,
    /// CrewAI APIs.
    CrewAi,
}

/// Privileged sink type reachable from an agent tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PrivilegedSink {
    /// Process execution through Python subprocess/os.system or Node child_process.
    ProcessExecution,
    /// Filesystem write through Node fs.writeFile/writeFileSync.
    FileWrite,
}

/// Extracted agentic tool edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgenticToolEdge {
    /// Framework family.
    pub framework: AgenticFramework,
    /// Tool registration label when statically visible.
    pub tool_name: Option<String>,
    /// Privileged sink reached from the tool body.
    pub sink: PrivilegedSink,
    /// 1-indexed line where the tool registration was observed.
    pub line: u32,
    /// True when a sandbox, allowlist, or containment boundary is present.
    pub sandboxed: bool,
}

/// Extracted agentic call graph summary.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AgenticCallGraph {
    /// Framework markers present in the source.
    pub frameworks: Vec<AgenticFramework>,
    /// Whether a user-controlled prompt source is visible.
    pub prompt_input_visible: bool,
    /// Tool edges that reach privileged sinks.
    pub tool_edges: Vec<AgenticToolEdge>,
}

/// Extract a lightweight agentic execution graph from Python or TypeScript-like source.
pub fn extract_agentic_call_graph(language: &str, source: &[u8]) -> AgenticCallGraph {
    if !matches!(language, "py" | "js" | "jsx" | "ts" | "tsx") {
        return AgenticCallGraph::default();
    }

    let text = String::from_utf8_lossy(source);
    let lower = text.to_ascii_lowercase();
    let mut graph = AgenticCallGraph {
        frameworks: detect_frameworks(&lower),
        prompt_input_visible: has_prompt_input(&lower),
        tool_edges: Vec::new(),
    };
    if graph.frameworks.is_empty() {
        return graph;
    }

    let sandboxed = has_sandbox_boundary(&lower);
    let mut sinks = Vec::new();
    if has_process_sink(&lower) {
        sinks.push(PrivilegedSink::ProcessExecution);
    }
    if has_file_write_sink(&lower) {
        sinks.push(PrivilegedSink::FileWrite);
    }
    if sinks.is_empty() || !has_agent_tool_registration(&lower) {
        return graph;
    }

    let line = first_tool_registration_line(&text);
    let tool_name = extract_tool_name(&text);
    for framework in graph.frameworks.clone() {
        for sink in &sinks {
            graph.tool_edges.push(AgenticToolEdge {
                framework,
                tool_name: tool_name.clone(),
                sink: *sink,
                line,
                sandboxed,
            });
        }
    }

    graph
}

/// Emit privilege-escalation findings for unsandboxed agentic tool flows.
pub fn find_agentic_privilege_escalations(
    language: &str,
    source: &[u8],
    label: &str,
) -> Vec<StructuredFinding> {
    let graph = extract_agentic_call_graph(language, source);
    if !graph.prompt_input_visible {
        return Vec::new();
    }

    graph
        .tool_edges
        .into_iter()
        .filter(|edge| !edge.sandboxed)
        .map(|edge| {
            let material = format!(
                "security:agentic_privilege_escalation:{label}:{:?}:{:?}:{:?}:{}",
                edge.framework, edge.tool_name, edge.sink, edge.line
            );
            StructuredFinding {
                id: "security:agentic_privilege_escalation".to_string(),
                file: Some(label.to_string()),
                line: Some(edge.line),
                fingerprint: short_fingerprint(material.as_bytes()),
                severity: Some("KevCritical".to_string()),
                remediation: Some(
                    "Insert a sandbox, allowlist, and capability boundary before routing prompt input to local agent tools."
                        .to_string(),
                ),
                docs_url: None,
                exploit_witness: None,
                upstream_validation_absent: false,
                ..Default::default()
            }
        })
        .collect()
}

fn detect_frameworks(lower: &str) -> Vec<AgenticFramework> {
    let mut frameworks = Vec::new();
    if lower.contains("langchain") || lower.contains("@langchain") {
        frameworks.push(AgenticFramework::LangChain);
    }
    if lower.contains("autogen") {
        frameworks.push(AgenticFramework::AutoGen);
    }
    if lower.contains("crewai") || lower.contains("crew ai") {
        frameworks.push(AgenticFramework::CrewAi);
    }
    frameworks
}

fn has_prompt_input(lower: &str) -> bool {
    lower.contains("input(")
        || lower.contains("request.")
        || lower.contains("req.body")
        || lower.contains("req.query")
        || lower.contains("user_prompt")
        || lower.contains("userprompt")
        || lower.contains("prompt")
}

fn has_agent_tool_registration(lower: &str) -> bool {
    lower.contains("tool(")
        || lower.contains("tool.from_function")
        || lower.contains("structuredtool")
        || lower.contains("dynamictool")
        || lower.contains("@tool")
        || lower.contains("agenttool")
        || lower.contains("tools=[")
        || lower.contains("tools: [")
        || lower.contains("tool =")
        || lower.contains("new tool")
}

fn has_process_sink(lower: &str) -> bool {
    lower.contains("subprocess.")
        || lower.contains("os.system")
        || lower.contains("child_process")
        || lower.contains("execsync")
        || lower.contains("spawn(")
        || lower.contains("exec(")
}

fn has_file_write_sink(lower: &str) -> bool {
    lower.contains("fs.writefile")
        || lower.contains("writefilesync")
        || lower.contains("filesystem.write")
        || lower.contains("path.write_text")
}

fn has_sandbox_boundary(lower: &str) -> bool {
    lower.contains("sandbox")
        || lower.contains("allowlist")
        || lower.contains("denylist")
        || lower.contains("seccomp")
        || lower.contains("capability")
        || lower.contains("jail")
        || lower.contains("validate_tool_input")
        || lower.contains("safe_tool")
}

fn first_tool_registration_line(text: &str) -> u32 {
    for (idx, line) in text.lines().enumerate() {
        let lower = line.to_ascii_lowercase();
        if has_agent_tool_registration(&lower) {
            return idx as u32 + 1;
        }
    }
    1
}

fn extract_tool_name(text: &str) -> Option<String> {
    for line in text.lines() {
        if let Some(name) = extract_after_key(line, "name=\"") {
            return Some(name);
        }
        if let Some(name) = extract_after_key(line, "name='") {
            return Some(name);
        }
        if let Some(name) = extract_after_key(line, "name: \"") {
            return Some(name);
        }
        if let Some(name) = extract_after_key(line, "name: '") {
            return Some(name);
        }
    }
    None
}

fn extract_after_key(line: &str, key: &str) -> Option<String> {
    let start = line.find(key)? + key.len();
    let quote = key.chars().last()?;
    let rest = &line[start..];
    let end = rest.find(quote)?;
    let value = rest[..end].trim();
    (!value.is_empty()).then(|| value.to_string())
}

fn short_fingerprint(bytes: &[u8]) -> String {
    let digest = blake3::hash(bytes);
    digest.as_bytes()[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn langchain_prompt_to_subprocess_emits_privilege_escalation() {
        let source = br#"
from langchain.tools import Tool
import subprocess

user_prompt = input("prompt: ")

def run_shell(cmd):
    return subprocess.check_output(cmd, shell=True)

tools = [Tool(name="shell", func=run_shell)]
agent.run(user_prompt)
"#;

        let findings = find_agentic_privilege_escalations("py", source, "agent.py");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "security:agentic_privilege_escalation");
        assert_eq!(findings[0].severity.as_deref(), Some("KevCritical"));
    }

    #[test]
    fn typescript_langchain_prompt_to_writefile_emits_privilege_escalation() {
        let source = br#"
import { DynamicTool } from "langchain/tools";
import fs from "fs";

const userPrompt = req.body.prompt;
const writer = new DynamicTool({
  name: "writer",
  func: async (input) => fs.writeFile("out.txt", input, () => {})
});
agent.call({ input: userPrompt, tools: [writer] });
"#;

        let findings = find_agentic_privilege_escalations("ts", source, "agent.ts");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "security:agentic_privilege_escalation");
    }

    #[test]
    fn sandboxed_agent_tool_does_not_emit_privilege_escalation() {
        let source = br#"
from crewai import Agent
from langchain.tools import Tool
import subprocess

user_prompt = input("prompt: ")
sandbox = CapabilitySandbox(allowlist=["echo"])

def run_shell(cmd):
    validate_tool_input(cmd)
    return subprocess.check_output(cmd, shell=True)

tools = [Tool(name="shell", func=run_shell)]
"#;

        let findings = find_agentic_privilege_escalations("py", source, "safe_agent.py");

        assert!(findings.is_empty());
    }
}
