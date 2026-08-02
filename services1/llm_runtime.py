# ============================================================
# AEGIS AI CONTROL TOWER
# ENTERPRISE LLM RUNTIME
# Shared Runtime for All AI Agents
# Qwen + Ollama
# ============================================================

from __future__ import annotations

import json
import time
import threading
from datetime import datetime
from typing import Dict, Any, Optional
from services1.cache_intelligence_service import (
    lookup_kv,
    lookup_prompt,
    store_kv,
    store_prompt,
)
# ============================================================
# DEBUG / TRACEBACK
# ============================================================

import traceback
from datetime import datetime
# ============================================================
# ENTERPRISE DEBUG LOGGER
# ============================================================
from pathlib import Path

import os

try:
    from groq import Groq
except Exception:
    Groq = None


# ============================================================
# ENTERPRISE PROVIDER REGISTRY
# ============================================================




GROQ_API_KEY = os.getenv("GROQ_API_KEY")

client = None


def get_groq_client():
    global client
    if client is not None:
        return client
    if Groq is None:
        raise RuntimeError(
            "groq package is not installed. Local Qwen runtime remains available "
            "for agents routed to LOCAL."
        )
    if not GROQ_API_KEY:
        raise RuntimeError(
            "GROQ_API_KEY is not configured. Set the environment variable "
            "to enable Groq-backed LLM agents, or run the demo with cached/rule-based outputs."
        )
    client = Groq(api_key=GROQ_API_KEY)
    return client

PROJECT_ROOT = Path(__file__).resolve().parent.parent

LOG_DIR = PROJECT_ROOT / "logs"

LOG_DIR.mkdir(exist_ok=True)

DEBUG_LOG = LOG_DIR / "aegis_runtime_debug.log"
#DEBUG_LOG = "aegis_runtime_debug.log"


def debug_log(message):

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    line = f"[{timestamp}] {message}"

    print(line)

    try:

        with open(
            DEBUG_LOG,
            "a",
            encoding="utf-8"
        ) as f:

            f.write(line + "\n")

    except Exception:

        pass


# ============================================================
# ENTERPRISE TRACEBACK LOGGER
# ============================================================

def log_exception(stage):

    debug_log("")
    debug_log("=" * 100)
    debug_log(f"FAILED STAGE : {stage}")
    debug_log("=" * 100)

    traceback.print_exc()

    try:

        with open(
            DEBUG_LOG,
            "a",
            encoding="utf-8"
        ) as f:

            traceback.print_exc(file=f)

    except Exception:

        pass

    debug_log("=" * 100)
    debug_log("")

import torch

from langchain_community.llms import Ollama




# ============================================================
# RUNTIME METADATA
# ============================================================

SERVICE_NAME = "AEGIS Enterprise LLM Runtime"

SERVICE_VERSION = "1.0"

SERVICE_STATUS = "ACTIVE"
ACTIVE_PROVIDER = "LOCAL"

ACTIVE_MODEL = "Qwen Local Runtime"

# ============================================================
# ENTERPRISE PROVIDER ROUTER
# ============================================================

DEFAULT_PROVIDER = "LOCAL"

PROVIDER_MAP = {

    # ----------------------------
    # LOCAL LLM
    # ----------------------------

    "Planner Agent": "LOCAL",

    "Reflection Agent": "LOCAL",

    "Trust Agent": "LOCAL",

    "Governance Agent": "LOCAL",

    "Recommendation Agent": "LOCAL",

    "Validator": "LOCAL",

    "Query Rewrite Agent": "LOCAL",

    "Hallucination Validator": "LOCAL",

    "Output Validator": "LOCAL",

    "Compliance Agent": "LOCAL",

    "Executive Agent": "LOCAL",

    "Executive Summary": "LOCAL",

    "Narrative Agent": "LOCAL"

}


# ============================================================
# MODEL CONFIGURATION
# ============================================================

#QWEN_MODEL_NAME = "Qwen/Qwen2.5-0.5B-Instruct"
#QWEN_MODEL_NAME = "Qwen/Qwen2.5-3B-Instruct"

#OLLAMA_MODEL_NAME = "llama3.1"


from pathlib import Path

HF_CACHE = Path.home() / ".cache" / "huggingface" / "hub"

def resolve_qwen_model():

    candidates = [

        "Qwen2.5-0.5B-Instruct",

        "Qwen2.5-1.5B-Instruct",

        "Qwen2.5-3B-Instruct"

    ]


    for model in candidates:

        root = HF_CACHE / f"models--Qwen--{model}" / "snapshots"

        if not root.exists():
            continue

        snapshots = sorted(
            [p for p in root.iterdir() if p.is_dir()],
            key=lambda x: x.stat().st_mtime,
            reverse=True
        )

        if snapshots:

            print(f"[LLM] Using local model: {snapshots[0]}")

            return str(snapshots[0])

    print("[LLM] Falling back to HuggingFace")

    return "Qwen/Qwen2.5-0.5B-Instruct"
QWEN_MODEL_NAME = resolve_qwen_model()
ACTIVE_MODEL = QWEN_MODEL_NAME
print("=" * 80)
print("ACTIVE MODEL =", QWEN_MODEL_NAME)
print("=" * 80)
#OLLAMA_MODEL_NAME = "tinyllama:latest"
OLLAMA_MODEL_NAME = "Groq Validation"

DEVICE = (

    "cuda"

    if torch.cuda.is_available()

    else "cpu"

)
# ============================================================
# SINGLETON RUNTIME
# ============================================================

_runtime_lock = threading.Lock()

_runtime_instance = None


# ============================================================
# ENTERPRISE LLM RUNTIME
# ============================================================

class EnterpriseLLMRuntime:

    def __init__(self):

        self.tokenizer = None
        self.model = None
        self.qwen = None
        self.ollama = None

        self.device = DEVICE
        self.loaded = False
        self.started_at = datetime.now().isoformat()

        # ----------------------------------------------------
        # Model Registry
        # ----------------------------------------------------

        self.model_registry = {

            "reasoning_model": QWEN_MODEL_NAME,

            "validator_model": OLLAMA_MODEL_NAME

        }

        # ----------------------------------------------------
        # Telemetry
        # ----------------------------------------------------


        self.telemetry = {

            "total_calls": 0,

            "successful_calls": 0,

            "failed_calls": 0,

            "total_tokens": 0,

            "total_latency_ms": 0,

            "average_latency_ms": 0,

            "providers": {},

            "models": {},

            "agent_usage": {},

            "errors": []

        }

        self.agent_history = []

        self.prompt_history = []

        self.validation_history = []

    # ============================================================
    # LOAD ALL MODELS
    # ============================================================

    def load_models(self):

        if self.loaded:
            return

        with _runtime_lock:

            if self.loaded:
                return

            debug_log("=" * 80)
            debug_log("Initializing Enterprise Models")
            debug_log("=" * 80)

            debug_log("Starting load_qwen()")
            print(__file__)
            print(hasattr(self, "load_qwen"))
            self.load_qwen()
            debug_log("Completed load_qwen()")

            debug_log("Starting load_ollama()")
            self.load_ollama()
            debug_log("Completed load_ollama()")

            self.loaded = True

            debug_log("Enterprise Models Ready")
            debug_log("=" * 80)
    # ============================================================
# PROVIDER RESOLUTION
# ============================================================

    def resolve_provider(

        self,

        agent_name

    ):

        provider = PROVIDER_MAP.get(

            agent_name,

            DEFAULT_PROVIDER

        )

        debug_log(

            f"{agent_name} Provider -> {provider}"

        )

        return provider

    # ============================================================
    # LOAD QWEN MODEL
    # ============================================================
# ============================================================
# LOAD QWEN (Groq Backend)
# ============================================================


    # ============================================================
# LOAD LOCAL QWEN MODEL
# ============================================================


# ============================================================
# LOAD LOCAL QWEN MODEL (CPU Optimized)
# Windows 11 | 16GB RAM | HuggingFace
# ============================================================

    def load_qwen(self):

        if self.qwen is not None:

            debug_log("=" * 80)
            debug_log("Local Qwen already loaded.")
            debug_log("=" * 80)

            return

        debug_log("=" * 80)
        debug_log("Loading Local Qwen Model")
        debug_log("=" * 80)

        try:

            from transformers import (

                AutoTokenizer,

                AutoModelForCausalLM,

                pipeline

            )

            debug_log(
                f"Model Path : {QWEN_MODEL_NAME}"
            )

            # --------------------------------------------------------
            # Tokenizer
            # --------------------------------------------------------

            self.tokenizer = AutoTokenizer.from_pretrained(

                QWEN_MODEL_NAME,

                trust_remote_code=True,

                use_fast=True

            )

            # --------------------------------------------------------
            # Model
            # --------------------------------------------------------

            self.model = AutoModelForCausalLM.from_pretrained(

                QWEN_MODEL_NAME,

                trust_remote_code=True,

                torch_dtype=torch.float32,

                low_cpu_mem_usage=True

            )

            # --------------------------------------------------------
            # Pipeline
            # --------------------------------------------------------

            self.qwen = pipeline(

                task="text-generation",

                model=self.model,

                tokenizer=self.tokenizer,

                device=-1,                      # CPU

                do_sample=False,

                temperature=0.2,

                max_new_tokens=256,

                repetition_penalty=1.05,

                return_full_text=False

            )

            self.loaded = True

            debug_log("=" * 80)
            debug_log("Local Qwen Loaded Successfully")
            debug_log(f"Model  : {QWEN_MODEL_NAME}")
            debug_log(f"Device : CPU")
            debug_log("=" * 80)

        except Exception as ex:

            debug_log("=" * 80)
            debug_log(f"FAILED LOADING LOCAL QWEN : {ex}")
            debug_log("=" * 80)

            log_exception("load_qwen")

            raise

    # LOAD OLLAMA
    # ============================================================
    def load_ollama(self):

        debug_log("Skipping Ollama initialization")

        self.ollama = None

        return

    # QWEN INVOCATION ENGINE
    # ============================================================


    # ============================================================
# GROQ INVOCATION ENGINE
# Enterprise Version with 429 Retry
# ============================================================

  # ============================================================
    # GROQ INVOCATION ENGINE
    # Enterprise Version with Retry + Telemetry
    # ============================================================

    def invoke_qwen(
        self,
        prompt,
        system_prompt="",
        temperature=0.2,
        max_tokens=1024,
        agent_name="Reasoning Agent"
    ):

        import time

        MAX_RETRIES = 5

        last_error = None

        if not GROQ_API_KEY:
            debug_log(
                f"{agent_name}: GROQ_API_KEY not configured. Falling back to local Qwen runtime."
            )
            return self.invoke_local_qwen(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=temperature,
                max_tokens=max_tokens,
                agent_name=agent_name
            )

        for attempt in range(MAX_RETRIES):

            start = time.time()

            try:

                debug_log("=" * 80)
                debug_log(f"{agent_name}: Using GROQ")
                debug_log(f"Attempt {attempt + 1}/{MAX_RETRIES}")
                debug_log("=" * 80)

                response = get_groq_client().chat.completions.create(

                    model=ACTIVE_MODEL,

                    messages=[

                        {
                            "role": "system",
                            "content": system_prompt
                        },

                        {
                            "role": "user",
                            "content": prompt
                        }

                    ],

                    temperature=temperature,

                    max_tokens=max_tokens

                )

                output = response.choices[0].message.content

                latency = int(

                    (time.time() - start) * 1000

                )

                telemetry = self.build_telemetry(

                    agent_name=agent_name,

                    provider="GROQ",

                    model=ACTIVE_MODEL,

                    prompt=prompt,

                    response=output,

                    latency=latency,

                    status="SUCCESS"

                )

                debug_log(

                    f"{agent_name}: GROQ completed successfully."

                )

                return {

                    "success": True,

                    "content": output,

                    "telemetry": telemetry

                }

            except Exception as ex:

                latency = int(

                    (time.time() - start) * 1000

                )

                last_error = ex

                error_message = str(ex)

                self.build_telemetry(

                    agent_name=agent_name,

                    provider="GROQ",

                    model=ACTIVE_MODEL,

                    prompt=prompt,

                    response="",

                    latency=latency,

                    status="FAILED"

                )

                debug_log("=" * 80)
                debug_log(f"{agent_name}: ERROR")
                debug_log(error_message)
                debug_log("=" * 80)

                # ----------------------------------------------------
                # Handle Rate Limit (HTTP 429)
                # ----------------------------------------------------

                if "429" in error_message:

                    wait = min(
                        2 ** attempt,
                        20
                    )

                    debug_log(

                        f"Rate limit detected. Sleeping for {wait} second(s)..."

                    )

                    time.sleep(wait)

                    continue

                # ----------------------------------------------------
                # Any Other Error
                # ----------------------------------------------------

                log_exception("invoke_qwen")

                return {

                    "success": False,

                    "error": error_message

                }

        # ------------------------------------------------------------
        # All retries exhausted
        # ------------------------------------------------------------

        debug_log("=" * 80)
        debug_log(f"{agent_name}: Maximum retry limit exceeded.")
        debug_log("=" * 80)

        return {

            "success": False,

            "error": str(last_error)

        }
    # ============================================================
# LOCAL QWEN
# ============================================================
# ============================================================
# LOCAL QWEN INVOCATION ENGINE (CPU)
# ============================================================

    def invoke_local_qwen(
        self,
        prompt,
        system_prompt="",
        temperature=0.2,
        max_tokens=256,
        agent_name="Local Reasoning Agent"
    ):

        import time

        start = time.time()

        try:

            if self.qwen is None:

                debug_log(
                    "Local model not loaded. Loading now..."
                )

                self.load_qwen()

            debug_log(
                f"{agent_name}: Using LOCAL Qwen"
            )

            final_prompt = f"""

    {system_prompt}

    User:

    {prompt}

    Assistant:

    """

            output = self.qwen(

                final_prompt,

                max_new_tokens=max_tokens,

                temperature=temperature,

                do_sample=False

            )

            if (

                isinstance(output, list)

                and len(output) > 0

            ):

                text = output[0].get(

                    "generated_text",

                    ""

                )

            else:

                text = str(output)

            latency = int(

                (time.time() - start) * 1000

            )

            telemetry = self.build_telemetry(

                agent_name=agent_name,

                provider="LOCAL",

                model=QWEN_MODEL_NAME,

                prompt=prompt,

                response=text,

                latency=latency,

                status="SUCCESS"

            )

            debug_log(

                f"{agent_name}: Local inference completed"

            )

            return {

                "success": True,

                "content": text,

                "telemetry": telemetry

            }

        except Exception as ex:

            latency = int(

                (time.time() - start) * 1000

            )

            self.build_telemetry(

                agent_name=agent_name,

                provider="LOCAL",

                model=QWEN_MODEL_NAME,

                prompt=prompt,

                response="",

                latency=latency,

                status="FAILED"

            )

            debug_log(

                f"{agent_name}: Local inference FAILED"

            )

            log_exception("invoke_local_qwen")

            return {

                "success": False,

                "error": str(ex)

            }


    # ============================================================
    # OLLAMA VALIDATION ENGINE
    # ============================================================
    def invoke_ollama(
        self,
        prompt: str,
        agent_name: str = "Validator"
    ) -> Dict[str, Any]:

        debug_log(
            f"{agent_name}: Using local Qwen validation runtime"
        )

        return self.invoke_local_qwen(
            prompt=prompt,
            system_prompt="You are a banking validation agent.",
            temperature=0.0,
            max_tokens=512,
            agent_name=agent_name
        )

    # JSON EXTRACTION
    # ============================================================


    def extract_json(self, response):

        """
        Enterprise JSON Extractor (V2)

        Features
        --------
        âœ” Removes markdown code fences
        âœ” Finds the FIRST complete JSON object
        âœ” Supports JSON arrays
        âœ” Ignores trailing explanations
        âœ” Handles multiple JSON objects
        âœ” Never throws an exception
        """

        import json
        import re

        if response is None:

            return {
                "parsed": False,
                "raw_response": ""
            }

        if not isinstance(response, str):

            response = str(response)

        response = response.strip()

        # ----------------------------------------------------------
        # Remove Markdown
        # ----------------------------------------------------------

        response = re.sub(

            r"^```(?:json)?",

            "",

            response,

            flags=re.IGNORECASE

        )

        response = re.sub(

            r"```$",

            "",

            response

        ).strip()

        # ----------------------------------------------------------
        # Direct Parse
        # ----------------------------------------------------------

        try:

            parsed = json.loads(response)

            if isinstance(parsed, dict):

                parsed["parsed"] = True

                return parsed

            return {

                "parsed": True,

                "items": parsed

            }

        except Exception:

            pass

        # ----------------------------------------------------------
        # Find First Complete JSON Object
        # ----------------------------------------------------------

        start = response.find("{")

        while start != -1:

            depth = 0

            in_string = False

            escape = False

            for i in range(start, len(response)):

                ch = response[i]

                if escape:

                    escape = False

                    continue

                if ch == "\\":

                    escape = True

                    continue

                if ch == '"':

                    in_string = not in_string

                    continue

                if in_string:

                    continue

                if ch == "{":

                    depth += 1

                elif ch == "}":

                    depth -= 1

                    if depth == 0:

                        candidate = response[start:i + 1]

                        try:

                            parsed = json.loads(candidate)

                            if isinstance(parsed, dict):

                                parsed["parsed"] = True

                                return parsed

                            return {

                                "parsed": True,

                                "items": parsed

                            }

                        except Exception:

                            break

            start = response.find("{", start + 1)

        # ----------------------------------------------------------
        # Find First JSON Array
        # ----------------------------------------------------------

        start = response.find("[")

        while start != -1:

            depth = 0

            in_string = False

            escape = False

            for i in range(start, len(response)):

                ch = response[i]

                if escape:

                    escape = False

                    continue

                if ch == "\\":

                    escape = True

                    continue

                if ch == '"':

                    in_string = not in_string

                    continue

                if in_string:

                    continue

                if ch == "[":

                    depth += 1

                elif ch == "]":

                    depth -= 1

                    if depth == 0:

                        candidate = response[start:i + 1]

                        try:

                            parsed = json.loads(candidate)

                            return {

                                "parsed": True,

                                "items": parsed

                            }

                        except Exception:

                            break

            start = response.find("[", start + 1)

        # ----------------------------------------------------------
        # Failed
        # ----------------------------------------------------------

        return {

            "parsed": False,

            "raw_response": response

        }





    # ============================================================
    # TOKEN ESTIMATION
    # ============================================================

    def estimate_tokens(

        self,

        text: str

    ) -> int:

        if not text:

            return 0

        return int(

            len(text.split()) * 1.35

        )


    # ============================================================
    # ENTERPRISE TELEMETRY
    # ============================================================
    # ============================================================
# ENTERPRISE TELEMETRY
# ============================================================

    def build_telemetry(
        self,
        agent_name: str,
        provider: str,
        model: str,
        prompt: str,
        response: str,
        latency: int,
        status: str
    ) -> Dict[str, Any]:

        """
        Enterprise Telemetry Builder

        Captures:
            â€¢ Token Usage
            â€¢ Provider Usage
            â€¢ Model Usage
            â€¢ Agent Usage
            â€¢ Runtime Statistics
            â€¢ Success / Failure
            â€¢ Latency
        """

        input_tokens = self.estimate_tokens(prompt)
        output_tokens = self.estimate_tokens(response)
        total_tokens = input_tokens + output_tokens

        # --------------------------------------------------------
        # Initialize telemetry dictionaries if missing
        # --------------------------------------------------------

        self.telemetry.setdefault("successful_calls", 0)
        self.telemetry.setdefault("providers", {})
        self.telemetry.setdefault("models", {})
        self.telemetry.setdefault("agent_usage", {})
        self.telemetry.setdefault("errors", [])
        self.telemetry.setdefault("total_latency_ms", 0)

        # --------------------------------------------------------
        # Runtime Counters
        # --------------------------------------------------------

        self.telemetry["total_calls"] += 1

        if status.upper() == "SUCCESS":
            self.telemetry["successful_calls"] += 1
        else:
            self.telemetry["failed_calls"] += 1

        self.telemetry["total_tokens"] += total_tokens

        self.telemetry["total_latency_ms"] += latency

        self.telemetry["average_latency_ms"] = round(
            self.telemetry["total_latency_ms"] /
            max(self.telemetry["total_calls"], 1),
            2
        )

        # --------------------------------------------------------
        # Provider Statistics
        # --------------------------------------------------------

        self.telemetry["providers"].setdefault(provider, 0)
        self.telemetry["providers"][provider] += 1

        # --------------------------------------------------------
        # Model Statistics
        # --------------------------------------------------------

        self.telemetry["models"].setdefault(model, 0)
        self.telemetry["models"][model] += 1

        # --------------------------------------------------------
        # Agent Statistics
        # --------------------------------------------------------

        self.telemetry["agent_usage"].setdefault(agent_name, 0)
        self.telemetry["agent_usage"][agent_name] += 1

        # --------------------------------------------------------
        # Telemetry Object
        # --------------------------------------------------------

        telemetry = {

            "timestamp": datetime.now().isoformat(),

            "agent": agent_name,

            "provider": provider,

            "model": model,

            "status": status,

            "latency_ms": latency,

            "input_tokens": input_tokens,

            "output_tokens": output_tokens,

            "total_tokens": total_tokens,

            "success": status.upper() == "SUCCESS"

        }

        # --------------------------------------------------------
        # Runtime History
        # --------------------------------------------------------

        self.agent_history.append(telemetry)

        return telemetry
        # ============================================================
        # AGENT EXECUTION LOGGER
        # ============================================================

    def log_agent(

            self,

            agent,

            model,

            provider,

            prompt,

            response,

            latency,

            confidence,

            trust,

            validation_score,

            status

        ):

            self.agent_history.append({

                "timestamp":

                    datetime.now().isoformat(),

                "agent":

                    agent,

                "model":

                    model,

                "provider":

                    provider,

                "latency_ms":

                    latency,

                "confidence":

                    confidence,

                "trust_score":

                    trust,

                "validation_score":

                    validation_score,

                "status":

                    status

            })

            self.prompt_history.append({

                "agent":

                    agent,

                "prompt":

                    prompt,

                "response":

                    response

            })

        # ============================================================
        # RUNTIME HEALTH
        # ============================================================

    # ============================================================
    # ENTERPRISE RUNTIME HEALTH
    # ============================================================

    def runtime_health(self):

            total_calls = self.telemetry.get("total_calls", 0)

            successful_calls = self.telemetry.get("successful_calls", 0)

            failed_calls = self.telemetry.get("failed_calls", 0)

            average_latency = self.telemetry.get("average_latency_ms", 0)

            success_rate = round(

                successful_calls /

                max(total_calls, 1) * 100,

                2

            )

            if success_rate >= 95:

                status = "HEALTHY"

            elif success_rate >= 80:

                status = "WARNING"

            else:

                status = "CRITICAL"

            return {

                "service": SERVICE_NAME,

                "version": SERVICE_VERSION,

                "status": status,

                "provider": ACTIVE_PROVIDER,

                "model": ACTIVE_MODEL,

                "loaded": self.loaded,

                "device": self.device,

                "started_at": self.started_at,

                "success_rate": success_rate,

                "total_calls": total_calls,

                "successful_calls": successful_calls,

                "failed_calls": failed_calls,

                "average_latency_ms": average_latency,

                "telemetry": self.telemetry,

                "agent_history": self.agent_history,

                "prompt_history": self.prompt_history,

                "validation_history": self.validation_history

            }
        # ============================================================
        # RETRY WRAPPER
        # ============================================================
    # ============================================================
    # ENTERPRISE RETRY ENGINE
    # ============================================================

    def retry(

            self,

            function,

            retries=2,

            retry_name="Enterprise Runtime"

        ):

            import time

            last_exception = None

            for attempt in range(retries + 1):

                try:

                    if attempt > 0:

                        debug_log(

                            f"{retry_name} Retry "

                            f"{attempt}/{retries}"

                        )

                    return function()

                except Exception as ex:

                    last_exception = ex

                    if attempt < retries:

                        wait = 2 ** attempt

                        debug_log(

                            f"Waiting {wait}s..."

                        )

                        time.sleep(wait)

            self.telemetry.setdefault(

                "errors",

                []

            ).append(

                {

                    "timestamp": datetime.now().isoformat(),

                    "agent": retry_name,

                    "provider": ACTIVE_PROVIDER,

                    "model": ACTIVE_MODEL,

                    "error": str(last_exception)

                }

            )

            raise last_exception

        # GENERIC REASONING AGENT
        # ============================================================


        # ============================================================
        # GENERIC VALIDATION AGENT
        # ============================================================


# ============================================================
# GENERIC REASONING AGENT
# Enterprise Multi-LLM Runtime
# ============================================================

    def invoke_reasoning_agent(
            self,
            agent_name: str,
            system_prompt: str,
            user_prompt: str,
            temperature: float = 0.2,
            max_tokens: int = 512,
            expect_json: bool = True,
            runtime_state=None,
            **kwargs
        ):

            # --------------------------------------------------------
            # Load Runtime
            # --------------------------------------------------------

            if not self.loaded:

                debug_log(
                    "Loading Enterprise LLM Runtime..."
                )

                self.load_models()

            # --------------------------------------------------------
            # Decide Provider
            # --------------------------------------------------------

            provider = self.resolve_provider(
                agent_name
            )
            debug_log(
                f"{agent_name} -> Provider : {provider}"
            )

            model_id = QWEN_MODEL_NAME if provider == "LOCAL" else ACTIVE_MODEL
            cache_parameters = {
                "agent": agent_name,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "expect_json": expect_json,
            }
            kv_session = ""
            kv_key = f"{agent_name}|{system_prompt}|{user_prompt}|{cache_parameters}"
            if isinstance(runtime_state, dict):
                kv_session = str(runtime_state.get("runtime_id") or runtime_state.get("customer_id") or "")
            if kv_session:
                cached_result, cache_event = lookup_kv(kv_session, kv_key)
                if cached_result is not None:
                    cached_result["cache"] = cache_event
                    cached_result.setdefault("telemetry", {})["latency_ms"] = 0
                    runtime_state.setdefault("cache_events", []).append(cache_event)
                    if not isinstance(runtime_state.get("llm_trace"), list):
                        runtime_state["llm_trace"] = []
                    runtime_state.setdefault("llm_trace", []).append({
                        "agent": agent_name,
                        "provider": provider,
                        "model": model_id,
                        "status": "CACHED",
                        "cache_layer": "kv",
                        "latency_ms": 0,
                    })
                    return cached_result

            cached_result, cache_event = lookup_prompt(
                user_prompt,
                system_prompt=system_prompt,
                model_id=model_id,
                parameters=cache_parameters,
            )
            if cached_result is not None:
                cached_result["cache"] = cache_event
                cached_result.setdefault("telemetry", {})["latency_ms"] = 0
                if isinstance(runtime_state, dict):
                    runtime_state.setdefault("cache_events", []).append(cache_event)
                    if not isinstance(runtime_state.get("llm_trace"), list):
                        runtime_state["llm_trace"] = []
                    runtime_state.setdefault("llm_trace", []).append({
                        "agent": agent_name,
                        "provider": provider,
                        "model": model_id,
                        "status": "CACHED",
                        "cache_layer": "prompt",
                        "latency_ms": 0,
                    })
                if kv_session:
                    store_kv(kv_session, kv_key, cached_result)
                return cached_result

            # --------------------------------------------------------
            # Invoke Local Model
            # --------------------------------------------------------

            if provider == "LOCAL":

                result = self.retry(

                    lambda: self.invoke_local_qwen(

                        prompt=user_prompt,

                        system_prompt=system_prompt,

                        temperature=temperature,

                        max_tokens=max_tokens,

                        agent_name=agent_name

                    ),

                    retries=2,

                    retry_name=agent_name

                )

            # --------------------------------------------------------
            # Invoke Groq
            # --------------------------------------------------------

            else:

                result = self.retry(

                    lambda: self.invoke_qwen(

                        prompt=user_prompt,

                        system_prompt=system_prompt,

                        temperature=temperature,

                        max_tokens=max_tokens,

                        agent_name=agent_name

                    ),

                    retries=2,

                    retry_name=agent_name

                )

            # --------------------------------------------------------
            # Failure
            # --------------------------------------------------------

            if not result.get("success", False):

                debug_log(
                    f"{agent_name} failed."
                )

                return result

            # --------------------------------------------------------
            # Parse Output
            # --------------------------------------------------------

            output = result.get(
                "content",
                ""
            )

            if expect_json:

                parsed_result = self.extract_json(output)

                result["json_status"] = parsed_result

                if isinstance(parsed_result, dict):

                    if "data" in parsed_result:

                        parsed = parsed_result["data"]

                    elif parsed_result.get("parsed", False):

                        parsed = {

                            k: v

                            for k, v in parsed_result.items()

                            if k != "parsed"

                        }

                    else:

                        parsed = {}

                else:

                    parsed = {}

            else:

                parsed = output
            result["parsed_output"] = parsed
            # --------------------------------------------------------
            # Default Confidence
            # --------------------------------------------------------

            result.setdefault(
                "confidence",
                90
            )

            result.setdefault(
                "trust_score",
                90
            )

            # --------------------------------------------------------
            # Runtime State
            # --------------------------------------------------------


            if runtime_state is not None:

                # ----------------------------------------------------
                # Ensure llm_trace is always a list
                # ----------------------------------------------------

                if not isinstance(

                    runtime_state.get("llm_trace"),

                    list

                ):

                    debug_log(
                        "Repairing llm_trace (expected list)."
                    )

                    runtime_state["llm_trace"] = []

                result_telemetry = result.get(

                    "telemetry",

                    {}

                )

                runtime_state["llm_trace"].append(

                    {

                        "agent": agent_name,

                        "provider": provider,

                        "model": (

                            QWEN_MODEL_NAME

                            if provider == "LOCAL"

                            else ACTIVE_MODEL

                        ),

                        "status": "SUCCESS",

                        "latency_ms": result.get(

                            "telemetry",

                            {}

                        ).get(

                            "latency_ms",

                            0

                        ),

                        "input_tokens": result_telemetry.get(

                            "input_tokens",

                            result_telemetry.get(

                                "prompt_tokens",

                                0

                            )

                        ),

                        "output_tokens": result_telemetry.get(

                            "output_tokens",

                            result_telemetry.get(

                                "completion_tokens",

                                0

                            )

                        ),

                        "total_tokens": result_telemetry.get(

                            "total_tokens",

                            (

                                result_telemetry.get("input_tokens", 0) +

                                result_telemetry.get("output_tokens", 0)

                            )

                        ),

                        "cost_basis": "Token telemetry"

                    }

                )
            debug_log(
                f"{agent_name} completed successfully"
            )

            prompt_store_event = store_prompt(
                user_prompt,
                result,
                system_prompt=system_prompt,
                model_id=model_id,
                parameters=cache_parameters,
            )
            if kv_session:
                store_kv(kv_session, kv_key, result)
            if isinstance(runtime_state, dict):
                runtime_state.setdefault("cache_events", []).extend([cache_event, prompt_store_event])

            return result
    # ============================================================
    # VALIDATOR AGENT
    # ==== ========================================================
    def invoke_validator_agent(
            self,
            agent_name,
            system_prompt="",
            user_prompt="",
            prompt=None,
            temperature=0.0,
            max_tokens=512,
            expect_json=True,
            runtime_state=None,
            **kwargs
        ):

            if prompt is not None and not user_prompt:
                user_prompt = prompt

            return self.invoke_reasoning_agent(
                agent_name=agent_name,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                temperature=temperature,
                max_tokens=max_tokens,
                expect_json=expect_json,
                runtime_state=runtime_state
            )





        # ============================================================
        # SINGLETON ACCESS
        # ============================================================

def get_llm_runtime():

    global _runtime_instance

    if _runtime_instance is None:

        with _runtime_lock:

            if _runtime_instance is None:

                _runtime_instance = (

                    EnterpriseLLMRuntime()

                )

    return _runtime_instance


# ============================================================
# SHUTDOWN
# ============================================================

def shutdown_runtime():

    global _runtime_instance

    _runtime_instance = None


# ============================================================
# READY TO USE RUNTIME
# ============================================================
print("LOADED:", __file__)
llm_runtime = get_llm_runtime()
#llm_runtime.load_models()

# ============================================================
# MODULE LEVEL WRAPPERS
# ============================================================

def invoke_reasoning_agent(*args, **kwargs):
    return llm_runtime.invoke_reasoning_agent(*args, **kwargs)


def invoke_validator_agent(*args, **kwargs):
    return llm_runtime.invoke_validator_agent(*args, **kwargs)
# ============================================================
# BACKWARD COMPATIBILITY
# ============================================================

def invoke_validation_agent(*args, **kwargs):
    return llm_runtime.invoke_validator_agent(*args, **kwargs)


def invoke_qwen(*args, **kwargs):
    return llm_runtime.invoke_qwen(*args, **kwargs)


def invoke_ollama(*args, **kwargs):
    return llm_runtime.invoke_ollama(*args, **kwargs)
# ============================================================
# EXPORTS
# ============================================================
__all__ = [

    "llm_runtime",

    "get_llm_runtime",

    "shutdown_runtime",

    "EnterpriseLLMRuntime",

    "invoke_reasoning_agent",

    "invoke_validator_agent",

    "invoke_validation_agent",

    "invoke_qwen",

    "invoke_ollama"

]
