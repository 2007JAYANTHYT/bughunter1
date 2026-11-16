"""
Configuration Manager for Bug Hunter Agent
Loads and validates all configuration files
"""

import os
import yaml
from pathlib import Path
from typing import Dict, Any, Optional, List
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings


class AuthConfig(BaseModel):
    type: str = "api_token"
    env_var: Optional[str] = None
    token: Optional[str] = None


class ScopeConfig(BaseModel):
    file: Optional[str] = None
    auto_fetch: bool = True


class PolicyConfig(BaseModel):
    file: Optional[str] = None
    max_severity: str = "P1"
    banned_types: List[str] = Field(default_factory=list)
    rate_limit: int = 100
    require_poc: bool = True
    poc_format: str = "video"


class NotificationsConfig(BaseModel):
    webhook: str = ""
    email: str = ""


class ProgramConfig(BaseModel):
    name: str
    platform: str = "custom"
    handle: str = ""
    enabled: bool = True
    auth: AuthConfig = Field(default_factory=AuthConfig)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    policy: PolicyConfig = Field(default_factory=PolicyConfig)
    custom_headers: List[str] = Field(default_factory=list)
    notifications: NotificationsConfig = Field(default_factory=NotificationsConfig)


class ScannerConfig(BaseModel):
    enabled: bool = True


class NucleiConfig(ScannerConfig):
    severity: List[str] = Field(default_factory=lambda: ["critical", "high", "medium", "low"])
    tags: List[str] = Field(default_factory=list)
    exclude_tags: List[str] = Field(default_factory=lambda: ["info", "dos", "fuzzing"])
    rate_limit: int = 150
    templates_path: str = "~/nuclei-templates-custom"
    custom_templates: bool = True


class DalFoxConfig(ScannerConfig):
    blind_xss: bool = True
    mining: bool = True
    worker: int = 50


class SQLMapConfig(ScannerConfig):
    level: int = 3
    risk: int = 2
    batch: bool = True
    threads: int = 10


class CustomPayloadsConfig(ScannerConfig):
    payload_dir: str = "payloads"


class ScannersConfig(BaseModel):
    nuclei: NucleiConfig = Field(default_factory=NucleiConfig)
    dalfox: DalFoxConfig = Field(default_factory=DalFoxConfig)
    sqlmap: SQLMapConfig = Field(default_factory=SQLMapConfig)
    custom_payloads: CustomPayloadsConfig = Field(default_factory=CustomPayloadsConfig)


class AIModelConfig(BaseModel):
    primary: str = "llama3.1:70b"
    code: str = "deepseek-coder:33b"
    reasoning: str = "nemotron3-ultra"
    fast: str = "phi3:14b"


class AIPromptsConfig(BaseModel):
    prompts_dir: str = "skills/hunting/prompts"


class AIHuntingConfig(BaseModel):
    enabled: bool = True
    models: AIModelConfig = Field(default_factory=AIModelConfig)
    max_tokens: int = 8192
    temperature: float = 0.1
    context_window: int = 128000
    prompts: AIPromptsConfig = Field(default_factory=AIPromptsConfig)


class SpecializedHuntersConfig(BaseModel):
    xss: bool = True
    sqli: bool = True
    ssrf: bool = True
    rce: bool = True
    auth: bool = True
    logic: bool = True
    api: bool = True
    mobile: bool = False
    cloud: bool = True
    supply_chain: bool = False


class PayloadsConfig(BaseModel):
    xss: List[str] = Field(default_factory=lambda: [
        "payloads/xss/reflected.txt",
        "payloads/xss/stored.txt",
        "payloads/xss/dom.txt",
        "payloads/xss/blind.txt"
    ])
    sqli: List[str] = Field(default_factory=lambda: [
        "payloads/sqli/error.txt",
        "payloads/sqli/blind.txt",
        "payloads/sqli/time.txt"
    ])
    ssrf: List[str] = Field(default_factory=lambda: [
        "payloads/ssrf/basic.txt",
        "payloads/ssrf/cloud.txt",
        "payloads/ssrf/bypass.txt"
    ])
    rce: List[str] = Field(default_factory=lambda: [
        "payloads/rce/deserialization.txt",
        "payloads/rce/template.txt",
        "payloads/rce/command.txt"
    ])


class HuntingConfig(BaseModel):
    threads: int = 50
    timeout: int = 30
    retries: int = 3
    follow_redirects: bool = True
    verify_ssl: bool = False
    rate_limit_rps: int = 10
    rate_limit_burst: int = 20
    strict_scope: bool = True
    allow_subdomains: bool = True
    scanners: ScannersConfig = Field(default_factory=ScannersConfig)
    ai_hunting: AIHuntingConfig = Field(default_factory=AIHuntingConfig)
    specialized: SpecializedHuntersConfig = Field(default_factory=SpecializedHuntersConfig)
    payloads: PayloadsConfig = Field(default_factory=PayloadsConfig)


class BrowserConfig(BaseModel):
    enabled: bool = True
    headless: bool = False
    browser: str = "firefox"
    viewport_width: int = 1920
    viewport_height: int = 1080
    record_video: bool = True
    video_dir: str = "evidence/videos"
    screenshot_on_success: bool = True
    screenshot_on_failure: bool = True
    screenshot_dir: str = "evidence/screenshots"
    har_capture: bool = True
    har_dir: str = "evidence/har"
    console_logs: bool = True
    network_logs: bool = True
    timeout: int = 60000
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    disable_automation_flags: bool = True
    disable_web_security: bool = True
    ignore_https_errors: bool = True


class BurpConfig(BaseModel):
    enabled: bool = True
    api_url: str = "http://127.0.0.1:1337"
    proxy_port: int = 8080
    proxy_host: str = "127.0.0.1"
    capture_traffic: bool = True
    export_format: str = "json"
    export_dir: str = "evidence/burp"
    use_mitmproxy_fallback: bool = True
    mitmproxy_port: int = 8081


class TerminalConfig(BaseModel):
    enabled: bool = True
    tool: str = "asciinema"
    output_dir: str = "evidence/terminal"
    record_all_sessions: bool = True


class AIValidationConfig(BaseModel):
    enabled: bool = True
    model: str = "llama3.1:70b"
    confidence_threshold: float = 0.8
    false_positive_checks: List[str] = Field(default_factory=lambda: [
        "reflection_analysis",
        "payload_execution",
        "impact_verification",
        "duplicate_detection"
    ])


class EvidenceConfig(BaseModel):
    create_package: bool = True
    package_dir: str = "evidence/packages"
    include: List[str] = Field(default_factory=lambda: [
        "screenshots", "videos", "har_files", "burp_exports",
        "terminal_recordings", "annotated_screenshots", "poc_code"
    ])
    annotate_screenshots: bool = True
    annotation_color: str = "red"
    annotation_width: int = 3


class ValidationConfig(BaseModel):
    browser: BrowserConfig = Field(default_factory=BrowserConfig)
    burp: BurpConfig = Field(default_factory=BurpConfig)
    terminal: TerminalConfig = Field(default_factory=TerminalConfig)
    ai_validation: AIValidationConfig = Field(default_factory=AIValidationConfig)
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)


class ConfigManager:
    """Central configuration manager"""

    def __init__(self, config_dir: str = "config"):
        self.config_dir = Path(config_dir)
        self._programs: Optional[List[ProgramConfig]] = None
        self._hunting: Optional[HuntingConfig] = None
        self._validation: Optional[ValidationConfig] = None
        self._ai_models: Optional[Dict[str, Any]] = None

    def load_programs(self) -> List[ProgramConfig]:
        """Load program configurations from programs.yaml"""
        if self._programs is not None:
            return self._programs

        programs_file = self.config_dir / "programs.yaml"
        if not programs_file.exists():
            example_file = self.config_dir / "programs.yaml.example"
            if example_file.exists():
                raise FileNotFoundError(
                    f"programs.yaml not found. Copy {example_file} to {programs_file} and configure."
                )
            raise FileNotFoundError(f"Programs config not found at {programs_file}")

        with open(programs_file, 'r') as f:
            data = yaml.safe_load(f)

        self._programs = [ProgramConfig(**p) for p in data.get('programs', [])]
        return self._programs

    def get_program(self, name: str) -> Optional[ProgramConfig]:
        """Get a specific program by name"""
        for program in self.load_programs():
            if program.name == name:
                return program
        return None

    def load_hunting(self) -> HuntingConfig:
        """Load hunting configuration"""
        if self._hunting is not None:
            return self._hunting

        hunting_file = self.config_dir / "hunting.yaml"
        if not hunting_file.exists():
            # Return defaults
            self._hunting = HuntingConfig()
            return self._hunting

        with open(hunting_file, 'r') as f:
            data = yaml.safe_load(f)

        self._hunting = HuntingConfig(**data.get('hunting', {}))
        return self._hunting

    def load_validation(self) -> ValidationConfig:
        """Load validation configuration"""
        if self._validation is not None:
            return self._validation

        validation_file = self.config_dir / "validation.yaml"
        if not validation_file.exists():
            self._validation = ValidationConfig()
            return self._validation

        with open(validation_file, 'r') as f:
            data = yaml.safe_load(f)

        self._validation = ValidationConfig(**data.get('validation', {}))
        return self._validation

    def load_ai_models(self) -> Dict[str, Any]:
        """Load AI models configuration"""
        if self._ai_models is not None:
            return self._ai_models

        ai_file = self.config_dir / "ai_models.yaml"
        if not ai_file.exists():
            return {}

        with open(ai_file, 'r') as f:
            self._ai_models = yaml.safe_load(f)

        return self._ai_models

    def get_env_var(self, name: str, default: str = "") -> str:
        """Get environment variable with optional default"""
        return os.getenv(name, default)

    def resolve_env_vars(self, config: Any) -> Any:
        """Recursively resolve environment variables in config values"""
        if isinstance(config, dict):
            return {k: self.resolve_env_vars(v) for k, v in config.items()}
        elif isinstance(config, list):
            return [self.resolve_env_vars(v) for v in config]
        elif isinstance(config, str) and config.startswith("${") and config.endswith("}"):
            env_name = config[2:-1]
            return self.get_env_var(env_name, config)
        return config

    def reload(self):
        """Force reload all configurations"""
        self._programs = None
        self._hunting = None
        self._validation = None
        self._ai_models = None


# Global config manager instance
config_manager = ConfigManager()


def get_config() -> ConfigManager:
    """Get the global config manager"""
    return config_manager