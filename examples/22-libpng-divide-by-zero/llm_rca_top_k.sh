# --- Variables Definition ---
BASE_DIR="/Racing-eval/examples/22-libpng-divide-by-zero"; \
RACING_CODE_DIR="/Racing-eval/Racing-code"; \
TOP_K=20; \
TEMPERATURE=0.2; \
\
# --- Step 1: GDB Crash Context ---
echo "[*] Step 1: Getting GDB crash context..." && \
(gdb -batch \
    -ex "run $BASE_DIR/seed/crash1.png" \
    -ex "bt full" \
    -ex "info registers" \
    -ex "x/32wx \$rsp" \
    -ex "x/20i \$pc" \
    -ex "quit" \
    --args "$BASE_DIR/pngimage_fuzz" > "$BASE_DIR/analysis_reports_manual/gdb_report.txt" 2>&1) || true && \
\
# --- Step 2: Compile and Run with AddressSanitizer (ASan) ---
echo "[*] Step 2.1: Compiling with ASan..." && \
cd $BASE_DIR/libpng-1.6.34 && \
make distclean &> /dev/null || true && \
CC=clang-6.0 CFLAGS="-g -O0 -fsanitize=address" ./configure --disable-shared &> /dev/null && \
make &> /dev/null && \
mv pngimage $BASE_DIR/pngimage-asan-sanitizer && \
echo "[*] Step 2.2: Generating ASan report..." && \
("$BASE_DIR/pngimage-asan-sanitizer" "$BASE_DIR/seed/crash1.png" > /dev/null 2> "$BASE_DIR/analysis_reports_manual/asan_report.txt") || true && \
\
# --- Step 3: Compile and Run with UndefinedBehaviorSanitizer (UBSan) ---
echo "[*] Step 3.1: Compiling with UBSan..." && \
cd $BASE_DIR/libpng-1.6.34 && \
make distclean &> /dev/null || true && \
CC=clang-6.0 CFLAGS="-g -O0 -fsanitize=undefined" ./configure --disable-shared &> /dev/null && \
make &> /dev/null && \
mv pngimage $BASE_DIR/pngimage-ubsan-undefined && \
echo "[*] Step 3.2: Generating UBSan report..." && \
("$BASE_DIR/pngimage-ubsan-undefined" "$BASE_DIR/seed/crash1.png" > /dev/null 2> "$BASE_DIR/analysis_reports_manual/ubsan_report.txt") || true && \
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
    "$BASE_DIR/pngimage_fuzz" @@ \
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
  --arg top_k_value "$TOP_K" \
  --arg temperature_value "$TEMPERATURE" \
  --arg output_format '{
  "top_k_predicates": [
      {
        "id_type": "...",
        "id": ...,
        "location": "...:...",
        "assembly": "...",
        "type": "...",
        "boundary_value": "...",
        "reason": "A concise explanation of why this predicate is the most important root cause."
      },
      {
        "//": "The second most important predicate object, with its own reason."
      }
    ]
  }' \
  --rawfile gdb_report "$BASE_DIR/analysis_reports_manual/gdb_report.txt" \
  --rawfile asan_report "$BASE_DIR/analysis_reports_manual/asan_report.txt" \
  --rawfile ubsan_report "$BASE_DIR/analysis_reports_manual/ubsan_report.txt" \
  --rawfile predicates "$BASE_DIR/analysis_reports_manual/predicate_list.json" \
  --arg crash_input "$(xxd -i "$BASE_DIR/seed/crash1.png")" \
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
              "# OUTPUT FORMAT\nYour entire response MUST be a single JSON object matching this structure exactly:\n" + $output_format + "\n\n" +
              "# TASK\n\n1.  **Analyze all five pieces of evidence** to understand the full context of the crash.\n2.  **\"Importance\"** is determined by how directly a predicate contributes to the final crash state. Predicates that occur earlier in the execution trace and create an unrecoverable faulty state are considered more important.\n3.  From the \"DYNAMIC PREDICATE TRACE\", select the **Top " + $top_k_value + "** most important predicates.\n4.  Your entire response MUST be a single JSON object adhering to the specified **OUTPUT FORMAT**.\n5.  The value of `\"top_k_predicates\"` MUST be a JSON array containing the " + $top_k_value + " selected predicate objects.\n6.  The array must be **ordered from most important to least important**.\n7.  For each predicate object in the array, copy its data from the evidence and add a `\"reason\"` key containing a concise explanation for your choice.\n"
            )
          }
        ]
      }
    ],
    "generationConfig": {
      "temperature": ($temperature_value | tonumber)
    }
  }' | curl -sS "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-pro:generateContent?key=$GEMINI_API_KEY" \
        -H 'Content-Type: application/json' \
        -X POST \
        -d @- > "$BASE_DIR/analysis_reports_manual/gemini_rca_report_raw.json" && \
\
# --- Step 6: Parse AI Response and Generate Final Report ---
echo "[*] Step 6: Parsing AI response and generating final report..." && \
\
jq -r '.candidates[0].content.parts[0].text' "$BASE_DIR/analysis_reports_manual/gemini_rca_report_raw.json" | sed 's/^```json//; s/```$//' | jq '.' > "$BASE_DIR/analysis_reports_manual/gemini_rca_report.json" && \
\
# Final Check
if [ $? -eq 0 ] && [ -s "$$BASE_DIR/analysis_reports_manual/gemini_rca_report.json" ]; then
    echo "[+] AI analysis successful. Final report saved to $$BASE_DIR/analysis_reports_manual/gemini_rca_report.json"
    # rm "$GEMINI_RAW_OUTPUT" # 可选：如果成功，删除原始输出文件
else
    echo "[!] ERROR: AI analysis step failed. Check the raw output for error messages:"
    cat "$$BASE_DIR/analysis_reports_manual/gemini_rca_report_raw.json"
    exit 1
fi