//! Solidity MEV risk synthesis.
//!
//! The module emits detector-only findings. It does not synthesize transaction
//! commands that execute sandwich attacks, flash-loan arbitrage, or any other
//! live on-chain extraction path.

use common::slop::{ExploitWitness, StructuredFinding};

/// Find AMM spot-price accounting that can be manipulated within one block.
pub fn find_mev_arbitrage_opportunities(source: &[u8]) -> Vec<StructuredFinding> {
    if parse_solidity(source).is_none() {
        return Vec::new();
    }
    collect_functions(source)
        .into_iter()
        .filter(|function| function.is_state_changing())
        .filter(|function| function.uses_unprotected_spot_price())
        .filter(|function| function.calculates_output_amount())
        .map(|function| function.to_finding(source))
        .collect()
}

#[derive(Debug, Clone)]
struct SolidityFunction {
    name: String,
    start: usize,
    lower: String,
}

impl SolidityFunction {
    fn is_state_changing(&self) -> bool {
        !(self.lower.contains(" view ")
            || self.lower.contains(" pure ")
            || self.lower.contains(" view returns")
            || self.lower.contains(" pure returns"))
    }

    fn uses_unprotected_spot_price(&self) -> bool {
        let spot_read = self.lower.contains(".balanceof(")
            || self.lower.contains("balanceof(address(this))")
            || self.lower.contains("getreserves()")
            || self.lower.contains("slot0()");
        let twap_guard = self.lower.contains("twap")
            || self.lower.contains("chainlink")
            || self.lower.contains("latestrounddata")
            || self.lower.contains("consult(")
            || self.lower.contains("pricecumulative")
            || self.lower.contains("timeweighted")
            || self.lower.contains("time-weighted");
        spot_read && !twap_guard
    }

    fn calculates_output_amount(&self) -> bool {
        (self.lower.contains("amountout")
            || self.lower.contains("amount_out")
            || self.lower.contains("outamount")
            || self.lower.contains("return "))
            && (self.lower.contains(" * ") || self.lower.contains(" / "))
    }

    fn to_finding(&self, source: &[u8]) -> StructuredFinding {
        StructuredFinding {
            id: "revenue:mev_arbitrage_opportunity".to_string(),
            file: None,
            line: Some(byte_to_line(source, self.start)),
            fingerprint: fingerprint("revenue:mev_arbitrage_opportunity", source, self.start),
            severity: Some("KevCritical".to_string()),
            remediation: Some(
                "State-changing AMM logic calculates token output from a manipulable spot-price read. Replace balance/getReserves/slot0 pricing with a TWAP or Chainlink oracle and enforce slippage bounds.".to_string(),
            ),
            exploit_witness: Some(ExploitWitness {
                source_function: self.name.clone(),
                source_label: "spot_price:balance_or_reserve".to_string(),
                sink_function: self.name.clone(),
                sink_label: "sink:state_changing_swap_math".to_string(),
                call_chain: vec![self.name.clone()],
                repro_cmd: Some(format!(
                    "cast call <target-contract> \"{}(...)\" --rpc-url <fork-rpc>",
                    self.name
                )),
                reproduction_steps: Some(vec![
                    "Run only against a local fork or owned test deployment.".to_string(),
                    "Compare the read-only quoted output before and after simulated reserve skew."
                        .to_string(),
                    "Do not submit a state-changing transaction; this witness is detector-only."
                        .to_string(),
                ]),
                risk_classification: Some(
                    "KevCritical MEV risk via manipulable spot-price accounting".to_string(),
                ),
                path_proof: Some(
                    "state-changing function uses balanceOf/getReserves/slot0 output in amount math without TWAP guard".to_string(),
                ),
                upstream_validation_absent: true,
                ..ExploitWitness::default()
            }),
            upstream_validation_absent: true,
            ..StructuredFinding::default()
        }
    }
}

fn parse_solidity(source: &[u8]) -> Option<tree_sitter::Tree> {
    let mut parser = tree_sitter::Parser::new();
    let language = tree_sitter_solidity::LANGUAGE;
    parser.set_language(&language.into()).ok()?;
    parser.parse(source, None)
}

fn collect_functions(source: &[u8]) -> Vec<SolidityFunction> {
    let text = std::str::from_utf8(source).unwrap_or("");
    let lower = text.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut search_start = 0usize;
    while let Some(rel) = lower[search_start..].find("function ") {
        let start = search_start + rel;
        let Some(open_rel) = lower[start..].find('{') else {
            break;
        };
        if let Some(semi_rel) = lower[start..].find(';') {
            if semi_rel < open_rel {
                search_start = start + semi_rel + 1;
                continue;
            }
        }
        let open = start + open_rel;
        let Some(end) = matching_brace(source, open) else {
            break;
        };
        let function_text = text[start..=end].to_string();
        out.push(SolidityFunction {
            name: extract_function_name(&function_text).unwrap_or_else(|| "unknown".to_string()),
            start,
            lower: function_text.to_ascii_lowercase(),
        });
        search_start = end + 1;
    }
    out
}

fn matching_brace(source: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (idx, byte) in source.iter().enumerate().skip(open) {
        match byte {
            b'{' => depth = depth.saturating_add(1),
            b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}

fn extract_function_name(text: &str) -> Option<String> {
    let trimmed = text.trim_start();
    let after_function = trimmed.strip_prefix("function ")?;
    let name = after_function
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .next()?;
    (!name.is_empty()).then(|| name.to_string())
}

fn byte_to_line(source: &[u8], offset: usize) -> u32 {
    let capped = offset.min(source.len());
    source[..capped]
        .iter()
        .filter(|byte| **byte == b'\n')
        .count() as u32
        + 1
}

fn fingerprint(rule: &str, source: &[u8], offset: usize) -> String {
    let start = offset.saturating_sub(64);
    let end = source.len().min(offset.saturating_add(128));
    let mut hasher = blake3::Hasher::new();
    hasher.update(rule.as_bytes());
    hasher.update(b":");
    hasher.update(&source[start..end]);
    hasher.finalize().to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_mock_spot_price_mev_arbitrage_opportunity() {
        let source = br#"
pragma solidity ^0.8.20;
interface IERC20 { function balanceOf(address owner) external view returns (uint256); }
contract Pool {
    IERC20 token0;
    IERC20 token1;
    function swap(uint256 amountIn) external returns (uint256 amountOut) {
        uint256 reserve0 = token0.balanceOf(address(this));
        uint256 reserve1 = token1.balanceOf(address(this));
        amountOut = amountIn * reserve1 / reserve0;
        token1.transfer(msg.sender, amountOut);
    }
}
"#;
        let findings = find_mev_arbitrage_opportunities(source);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "revenue:mev_arbitrage_opportunity");
        assert_eq!(findings[0].severity.as_deref(), Some("KevCritical"));
        let repro = findings[0]
            .exploit_witness
            .as_ref()
            .and_then(|witness| witness.repro_cmd.as_deref())
            .unwrap_or("");
        assert!(repro.starts_with("cast call "));
        assert!(!repro.contains("cast send"));
    }

    #[test]
    fn twap_guard_suppresses_spot_price_mev_detector() {
        let source = br#"
pragma solidity ^0.8.20;
contract Pool {
    function swap(uint256 amountIn) external returns (uint256 amountOut) {
        uint256 twap = oracle.consult(address(token), amountIn);
        amountOut = twap;
    }
}
"#;
        assert!(find_mev_arbitrage_opportunities(source).is_empty());
    }
}
