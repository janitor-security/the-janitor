;; mock_rule.wat — Crucible fixture for the Wasm host-guest ABI test.
;;
;; This module always emits one `security:proprietary_rule` finding regardless
;; of the input source bytes, proving the full host-guest round-trip is
;; functional: engine compilation, memory I/O, fuel enforcement, and JSON
;; deserialisation into `StructuredFinding`.
;;
;; Output buffer layout:
;;   offset 0: JSON finding (59 bytes)
;;   `{"id":"security:proprietary_rule","file":null,"line":null}\n`
;;
;; Host-guest ABI compliance:
;;   - exports `memory`         (linear memory, >= 1 page)
;;   - exports `output_ptr`     () -> i32   (returns 0)
;;   - exports `analyze`        (i32, i32) -> i32  (returns 59)
(module
  (memory (export "memory") 2)

  ;; Static finding at offset 0 — written once at module instantiation.
  ;; 59 bytes: JSON object + newline terminator.
  (data (i32.const 0)
    "{\"id\":\"security:proprietary_rule\",\"file\":null,\"line\":null}\n"
  )

  ;; output_ptr() -> i32
  ;; Returns the base address of the findings buffer (always 0).
  (func (export "output_ptr") (result i32)
    i32.const 0
  )

  ;; analyze(src_ptr: i32, src_len: i32) -> i32
  ;; Ignores input; returns length of the static finding written at offset 0.
  (func (export "analyze") (param i32 i32) (result i32)
    i32.const 59
  )
)
