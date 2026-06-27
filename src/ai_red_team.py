import os
import sys
import json
import time
import requests

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from src.client import MultiHopperClient
from src.findings import record, Finding

GEMINI_KEY = os.environ.get("GEMINI_API_KEY", "")
GROQ_KEY   = os.environ.get("GROQ_API_KEY", "")

client = MultiHopperClient()
SOURCE = os.environ.get("SOURCE_WALLET", "")
DEST   = os.environ.get("RECIPIENT_WALLET", "")

SYSTEM_PROMPT = f"""
You are an autonomous AI Red-Team Agent testing the MultiHopper Solana API.
Your goal is to find logical validation errors, validation bypasses, race conditions, metadata gaps, or critical smart contract integrity vulnerabilities by interacting with the API client.

Available variables you must use for wallets:
- SOURCE_WALLET: "{SOURCE}"
- RECIPIENT_WALLET: "{DEST}"

You have access to a MultiHopperClient with the following helper methods:
1. client.create(source_owner, recipient, amount_raw, amount_tokens, hops, arrival_seconds, token_mint, token_decimals, token_symbol, external_id, overrides)
2. client.prepare(transfer_id)
3. client.confirm_broadcast(transfer_id, body)
4. client.get(transfer_id)
5. client.list(**params)
6. client.raw(method, path, body, idem_key) - for arbitrary path execution

Rules of execution:
- You will run in a loop for 10 turns.
- In each turn, you output a JSON action block to call a client method or raw API path.
- The execution result (HTTP status + response body) will be fed back to you.
- DO NOT test simple type constraints (e.g. sending text in number fields or negative numbers) because the API's static schema validates these.
- Focus your testing on LOGICAL AND STRUCTURAL gaps:
  - Mismatched amountRaw and amountTokens (e.g. amountRaw=1000000000 but amountTokens=0.000001).
  - Self-transfers (sourceOwner == recipientWallet).
  - Fake/spoofed signatures on confirm-broadcast (does it accept arbitrary strings?).
  - Invalid but syntactically correct Base58 Solana public keys for tokenMint or wallets (does it accept any 44-char base58 string?).
  - Duplicate externalId across different transfers.
  - Calling confirm-broadcast before prepare, or missing keeper signatures.
  - Race conditions by triggering concurrent operations or duplicate keys.

Output format for your turn MUST be ONLY a JSON object:
{{
  "thought": "Why I am targeting this endpoint and what vulnerability I am testing.",
  "method": "create" | "prepare" | "confirm_broadcast" | "get" | "list" | "raw",
  "args": {{ ... }}
}}

Example:
{{
  "thought": "Testing if the API accepts sourceOwner == recipientWallet (self-transfer).",
  "method": "create",
  "args": {{
    "source_owner": "{SOURCE}",
    "recipient": "{SOURCE}",
    "amount_raw": "100000000",
    "amount_tokens": "0.1"
  }}
}}
"""


def query_gemma4(messages: list) -> dict:
    if not GEMINI_KEY:
        return {}
    try:
        from google import genai
        from google.genai import types
        sdk_client = genai.Client()
        sdk_contents = []
        for m in messages:
            role = "user" if m["role"] == "user" else "model"
            sdk_contents.append(
                types.Content(
                    role=role,
                    parts=[types.Part.from_text(text=m["content"])]
                )
            )
        response = sdk_client.models.generate_content(
            model="gemma-4-26b-a4b-it",
            contents=sdk_contents
        )
        text = response.text or ""
        if "```json" in text:
            text = text.split("```json")[1].split("```")[0]
        elif "```" in text:
            text = text.split("```")[1].split("```")[0]
        return json.loads(text.strip())
    except ImportError:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemma-4-26b-a4b-it:generateContent?key={GEMINI_KEY}"
            contents = []
            for m in messages:
                contents.append({
                    "role": "user" if m["role"] == "user" else "model",
                    "parts": [{"text": m["content"]}]
                })
            resp = requests.post(url, json={"contents": contents}, timeout=30)
            resp.raise_for_status()
            text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
            if "```json" in text:
                text = text.split("```json")[1].split("```")[0]
            elif "```" in text:
                text = text.split("```")[1].split("```")[0]
            return json.loads(text.strip())
        except Exception:
            return {}
    except Exception:
        return {}


def query_llama33(messages: list) -> dict:
    if not GROQ_KEY:
        return {}
    try:
        url = "https://api.groq.com/openai/v1/chat/completions"
        resp = requests.post(url, headers={
            "Authorization": f"Bearer {GROQ_KEY}",
            "Content-Type": "application/json"
        }, json={
            "model": "llama-3.3-70b-versatile",
            "messages": messages,
            "temperature": 0.3,
            "response_format": {"type": "json_object"}
        }, timeout=30)
        resp.raise_for_status()
        text = resp.json()["choices"][0]["message"]["content"]
        return json.loads(text.strip())
    except Exception:
        return {}


def run_consensus_turn(messages: list) -> dict:
    prop_gemma = query_gemma4(messages)
    prop_llama = query_llama33(messages)

    if prop_gemma and not prop_llama:
        print("  [ORACLE] Gemma 4 active (Llama offline/no key)")
        return prop_gemma
    elif prop_llama and not prop_gemma:
        print("  [ORACLE] Llama 3.3 active (Gemma offline/no key)")
        return prop_llama
    elif not prop_gemma and not prop_llama:
        print("  [ORACLE] Error: Both models offline or keys missing.")
        return {}

    print(f"  [ORACLE Gemma 4] proposes: {prop_gemma.get('method')} → {(prop_gemma.get('thought') or '')[:60]}...")
    print(f"  [ORACLE Llama 3.3] proposes: {prop_llama.get('method')} → {(prop_llama.get('thought') or '')[:60]}...")

    if prop_gemma.get("method") == prop_llama.get("method") and list(prop_gemma.get("args", {}).keys()) == list(prop_llama.get("args", {}).keys()):
        print("  [ORACLE CONSENSUS] Agreement reached. Executing proposal.")
        return prop_gemma

    print("  [ORACLE DISAGREEMENT] Conflict detected. Invoking Gemma 4 as Consensus Referee...")
    referee_prompt = f"""
You are the Consensus Referee in a Multi-Model AI testing team.
Two security models have proposed different next steps for exploratory red-teaming of the MultiHopper Solana API:

Option A (Gemma 4):
{json.dumps(prop_gemma, indent=2)}

Option B (Llama 3.3):
{json.dumps(prop_llama, indent=2)}

Evaluate both proposals based on:
1. Which test is more logically sound for finding production-level validation gaps or vulnerabilities.
2. Avoiding duplicate tests or simple format constraint checks.

Choose the better proposal. Output ONLY the chosen proposal as a JSON object matching the exact structure of Option A or B.
"""
    try:
        referee_messages = messages + [{"role": "user", "content": referee_prompt}]
        decision = query_gemma4(referee_messages)
        if decision and "method" in decision:
            print(f"  [ORACLE REFEREE DECISION] Selected: {decision.get('method')} → {(decision.get('thought') or '')[:60]}...")
            return decision
    except Exception:
        pass

    print("  [ORACLE FALLBACK] Referee failed. Defaulting to Gemma 4 proposal.")
    return prop_gemma


def execute_action(action: dict) -> tuple[int, dict]:
    method = action.get("method")
    args = action.get("args", {})

    print(f"  [EXECUTE] Calling client.{method} with args: {args}")

    if method == "create":
        return client.create(
            source_owner=args.get("source_owner", SOURCE),
            recipient=args.get("recipient", DEST),
            amount_raw=args.get("amount_raw", "100000000"),
            amount_tokens=args.get("amount_tokens", "0.1"),
            hops=args.get("hops", 3),
            arrival_seconds=args.get("arrival_seconds", 300),
            token_mint=args.get("token_mint", "So11111111111111111111111111111111111111112"),
            token_decimals=args.get("token_decimals", 9),
            token_symbol=args.get("token_symbol", "SOL"),
            external_id=args.get("external_id"),
            overrides=args.get("overrides")
        )
    elif method == "prepare":
        return client.prepare(args.get("transfer_id", 0))
    elif method == "confirm_broadcast":
        return client.confirm_broadcast(args.get("transfer_id", 0), args.get("body", {}))
    elif method == "get":
        return client.get(args.get("transfer_id", 0))
    elif method == "list":
        return client.list(**args)
    elif method == "raw":
        return client.raw(
            method=args.get("http_method", "POST"),
            path=args.get("path", "/transfers"),
            body=args.get("body"),
            idem_key=args.get("idem_key")
        )
    else:
        return 0, {"error": f"Unknown method: {method}"}


def save_findings_log(new_text: str):
    path = "reports/ai_red_team_findings.md"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    
    timestamp = time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())
    run_header = f"\n\n---\n## AI Red-Team Run: {timestamp}\n\n"
    
    if os.path.exists(path):
        print(f"  [AI] Appending findings to existing registry: {path}")
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(run_header + new_text.strip())
    else:
        print(f"  [AI] Creating new findings registry: {path}")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# Autonomous AI Red Team Findings\n" + run_header + new_text.strip())


def run_ai_red_team():
    if not GEMINI_KEY and not GROQ_KEY:
        print("\n[AI RED TEAM] Skipping. Please set GEMINI_API_KEY or GROQ_API_KEY in .env.")
        return

    print("\n" + "="*60)
    print("STARTING AUTONOMOUS AI RED-TEAM ORACLE EXPLORATION")
    print(f"  Gemini (Gemma 4): {'Available' if GEMINI_KEY else 'Offline'}")
    print(f"  Groq (Llama 3.3): {'Available' if GROQ_KEY else 'Offline'}")
    print("="*60)

    messages = [
        {"role": "user", "content": SYSTEM_PROMPT},
        {"role": "user", "content": "Start turn 1. Decide your first target payload."}
    ]

    for turn in range(1, 11):
        print(f"\n--- TURN {turn}/10 ---")
        action = run_consensus_turn(messages)
        if not action or "method" not in action:
            print("  [AI RED TEAM] Invalid or empty response from Oracle.")
            break

        print(f"  [DECISION THOUGHT] {action.get('thought')}")
        status, response = execute_action(action)
        print(f"  [RESPONSE] HTTP {status}: {json.dumps(response)[:200]}")

        feedback = f"Result of turn {turn}: HTTP {status}. Response body: {json.dumps(response)}"
        messages.append({"role": "assistant", "content": json.dumps(action)})
        messages.append({"role": "user", "content": feedback + "\nDecide your next action block."})
        time.sleep(3)

    # Compile findings
    print("\n--- COMPILING AI RED TEAM FINDINGS ---")
    messages.append({
        "role": "user",
        "content": (
            "You have completed your 10 turns. Identify any logical bugs, validation gaps, "
            "or security vulnerabilities you found. Write a detailed security report. "
            "For each finding, provide: "
            "1. Title & Severity (Critical/High/Medium/Low) "
            "2. Vulnerability Description (Why the observed behavior is unsafe) "
            "3. Impact on automated agent workflows or fund routing "
            "4. Step-by-step reproduction path "
            "5. Proof-of-concept payload examples "
            "6. Suggested fix. "
            "Structure it cleanly as professional markdown."
        )
    })
    
    if GEMINI_KEY:
        try:
            from google import genai
            from google.genai import types
            sdk_client = genai.Client()
            sdk_contents = []
            for m in messages:
                role = "user" if m["role"] == "user" else "model"
                sdk_contents.append(
                    types.Content(
                        role=role,
                        parts=[types.Part.from_text(text=m["content"])]
                    )
                )
            response = sdk_client.models.generate_content(
                model="gemma-4-26b-a4b-it",
                contents=sdk_contents
            )
            text = response.text or ""
        except ImportError:
            try:
                url = f"https://generativelanguage.googleapis.com/v1beta/models/gemma-4-26b-a4b-it:generateContent?key={GEMINI_KEY}"
                contents = [{"role": "user" if m["role"] == "user" else "model", "parts": [{"text": m["content"]}]} for m in messages]
                resp = requests.post(url, json={"contents": contents}, timeout=30)
                text = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
            except Exception as e:
                print(f"Failed to generate final summary via REST: {e}")
                return
        except Exception as e:
            print(f"Failed to generate final summary via SDK: {e}")
            return
            
        print("\n=== AI EXPLORATORY FINDINGS ===")
        print(text)
        print("===============================")
        save_findings_log(text)

    elif GROQ_KEY:
        try:
            url = "https://api.groq.com/openai/v1/chat/completions"
            resp = requests.post(url, headers={
                "Authorization": f"Bearer {GROQ_KEY}",
                "Content-Type": "application/json"
            }, json={
                "model": "llama-3.3-70b-versatile",
                "messages": messages,
                "temperature": 0.3
            }, timeout=30)
            text = resp.json()["choices"][0]["message"]["content"]
            print("\n=== AI EXPLORATORY FINDINGS ===")
            print(text)
            print("===============================")
            save_findings_log(text)
        except Exception as e:
            print(f"Failed to generate final summary via Groq: {e}")


if __name__ == "__main__":
    import dotenv
    dotenv.load_dotenv()
    run_ai_red_team()
