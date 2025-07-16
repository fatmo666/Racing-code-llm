# --- Variables Definition ---
BASE_DIR="/Racing-eval/examples/21-ezXML-nullptr-dereference"; \
RACING_CODE_DIR="/Racing-eval/Racing-code"; \
\
# --- Step 1: GDB Crash Context ---
echo "[*] Step 1: Getting GDB crash context..." && \
(gdb -batch \
    -ex "run $BASE_DIR/seed/poc" \
    -ex "bt full" \
    -ex "info registers" \
    -ex "x/32wx \$rsp" \
    -ex "x/20i \$pc" \
    -ex "quit" \
    --args "$BASE_DIR/ezxml_fuzz" > "$BASE_DIR/analysis_reports_manual/gdb_report.txt" 2>&1) || true && \
\
# --- Step 2: Compile and Run with AddressSanitizer (ASan) ---
echo "[*] Step 2.1: Compiling with ASan..." && \
clang-6.0 -g -O0 -fsanitize=address -DEZXML_TEST \
    -o "$BASE_DIR/exzml-asan-sanitizer" \
    "$BASE_DIR/ezxml/ezxml.c" && \
echo "[*] Step 2.2: Generating ASan report..." && \
("$BASE_DIR/exzml-asan-sanitizer" "$BASE_DIR/seed/poc" > /dev/null 2> "$BASE_DIR/analysis_reports_manual/asan_report.txt") || true && \
\
# --- Step 3: Compile and Run with UndefinedBehaviorSanitizer (UBSan) ---
echo "[*] Step 3.1: Compiling with UBSan..." && \
clang-6.0 -g -O0 -fsanitize=undefined -DEZXML_TEST \
    -o "$BASE_DIR/exzml-ubsan-sanitizer" \
    "$BASE_DIR/ezxml/ezxml.c" && \
echo "[*] Step 3.2: Generating UBSan report..." && \
("$BASE_DIR/exzml-ubsan-sanitizer" "$BASE_DIR/seed/poc" > /dev/null 2> "$BASE_DIR/analysis_reports_manual/ubsan_report.txt") || true && \
\
# --- Step 4: Run Custom AFL Fuzzer (Potentially a long-running task) ---
echo "[*] Step 4: Starting custom afl-fuzz to generate predicate list..." && \
(cd "$RACING_CODE_DIR" && \
    ANALYZE_ONCE_OUTPATH="$BASE_DIR/analysis_reports_manual/predicate_list.json" \
    ./afl-fuzz \
    -C -d -m none \
    -i "$BASE_DIR/seed" \
    -o "$BASE_DIR/afl-workdir-batch0" \
    -s "$BASE_DIR/temp_data/trace-id.log" \
    -- \
    "$BASE_DIR/ezxml_fuzz" @@ \
) && \
\
# --- Step 5: Send Evidence to Gemini for Root-Cause Analysis (Robust Pipe Version) ---
echo "[*] Step 5: Sending evidence to Gemini for root-cause analysis..." && \
\
# Check for jq installation
if ! command -v jq &> /dev/null; then \
    echo "[!] ERROR: jq is not installed. Please install it (e.g., sudo apt-get install jq) and try again."; \
    exit 1; \
fi && \
\
# Check for API Key
if [ -z "$GEMINI_API_KEY" ]; then \
    echo "[!] ERROR: GEMINI_API_KEY environment variable is not set. Aborting."; \
    exit 1; \
fi && \
\
# 【关键修改】使用 jq 的 --rawfile 参数直接读取文件，然后通过管道将构建好的 JSON 发送给 curl
jq -n \
  --rawfile gdb_report "$BASE_DIR/analysis_reports_manual/gdb_report.txt" \
  --rawfile asan_report "$BASE_DIR/analysis_reports_manual/asan_report.txt" \
  --rawfile ubsan_report "$BASE_DIR/analysis_reports_manual/ubsan_report.txt" \
  --rawfile predicates "$BASE_DIR/analysis_reports_manual/predicate_list.json" \
  --arg crash_input "$(xxd -i "$BASE_DIR/seed/poc")" \
  '{
    "contents": [
      {
        "parts": [
          {
            "text": (
              "# MISSION\nYou are a vulnerability root-cause analysis bot. Your ONLY task is to identify the single line of code that is the fundamental root cause of the crash, based on the provided evidence.\n\n" +
              "# EVIDENCE\n\n" +
              "---\n## GDB CRASH CONTEXT\n" + $gdb_report + "\n---\n\n" +
              "---\n## ADDRESS SANITIZER REPORT\n" + $asan_report + "\n---\n\n" +
              "---\n## UNDEFINED SANITIZER REPORT\n" + $ubsan_report + "\n---\n\n" +
              "---\n## DYNAMIC PREDICATE TRACE\n" + $predicates + "\n---\n\n" +
              "---\n## CRASH INPUT\n" + $crash_input + "\n---\n\n" +
              "# TASK\n\nAnalyze all the evidence provided above. The root cause is the earliest point in the code where a faulty state is introduced without proper validation, which eventually leads to the final crash.\n\nYour entire response MUST be a single JSON object, with no other text before or after it. The JSON object must have ONLY the following two keys: \"vulnerability_type\" and \"root_cause_location\"."
            )
          }
        ]
      }
    ]
  }' | curl -sS "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent?key=$GEMINI_API_KEY" \
        -H 'Content-Type: application/json' \
        -X POST \
        -d @- > "$BASE_DIR/analysis_reports_manual/gemini_rca_report.json" && \
\
# Final Check
if [ $? -eq 0 ] && [ -s "$BASE_DIR/analysis_reports_manual/gemini_rca_report.json" ] && ! grep -q '"error"' "$BASE_DIR/analysis_reports_manual/gemini_rca_report.json"; then
    echo "[+] AI analysis successful. Report saved to analysis_reports_manual/gemini_rca_report.json"
else
    echo "[!] ERROR: AI analysis step failed. Check the final report for error messages:"
    cat "$BASE_DIR/analysis_reports_manual/gemini_rca_report.json"
    exit 1
fi