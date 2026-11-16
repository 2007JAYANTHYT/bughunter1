"""
Terminal Session Capture
Records terminal sessions for CLI-based exploit evidence
Uses asciinema and script command
"""

import asyncio
import os
import subprocess
import tempfile
import base64
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class TerminalEvidence:
    """Terminal session evidence"""
    session_name: str
    start_time: str
    end_time: Optional[str] = None
    recording_path: str = ""
    commands: List[Dict] = field(default_factory=list)
    output_size: int = 0
    duration_seconds: float = 0.0


class TerminalCapture:
    """Terminal session recording using asciinema or script"""

    def __init__(self, config_manager=None):
        from core.config_manager import get_config
        self.config = config_manager or get_config()
        self.output_dir = Path(self.config.load_validation().terminal.output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.current_session: Optional[TerminalEvidence] = None
        self.process = None
        self.use_asciinema = self.config.load_validation().terminal.tool == "asciinema"

    def start_recording(self, session_name: str) -> str:
        """Start terminal recording"""
        self.current_session = TerminalEvidence(
            session_name=session_name,
            start_time=datetime.utcnow().isoformat(),
        )

        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
        safe_name = "".join(c for c in session_name if c.isalnum() or c in '-_')

        if self.use_asciinema:
            filename = f"{safe_name}_{timestamp}.cast"
            self.current_session.recording_path = str(self.output_dir / filename)
            # Start asciinema recording
            self.process = subprocess.Popen(
                ["asciinema", "rec", "--quiet", self.current_session.recording_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        else:
            filename = f"{safe_name}_{timestamp}.typescript"
            self.current_session.recording_path = str(self.output_dir / filename)
            # Start script recording
            self.process = subprocess.Popen(
                ["script", "-q", "-c", "bash", self.current_session.recording_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

        return self.current_session.recording_path

    def stop_recording(self) -> TerminalEvidence:
        """Stop terminal recording"""
        if not self.current_session or not self.process:
            return None

        self.current_session.end_time = datetime.utcnow().isoformat()

        if self.use_asciinema:
            # Send exit command to asciinema
            self.process.stdin.write(b"exit\n")
            self.process.stdin.flush()
        else:
            # Send exit to script
            self.process.stdin.write(b"exit\n")
            self.process.stdin.flush()

        # Wait for process to finish
        self.process.wait(timeout=10)

        # Calculate duration
        start = datetime.fromisoformat(self.current_session.start_time)
        end = datetime.fromisoformat(self.current_session.end_time)
        self.current_session.duration_seconds = (end - start).total_seconds()

        # Get file size
        if Path(self.current_session.recording_path).exists():
            self.current_session.output_size = Path(self.current_session.recording_path).stat().st_size

        # Parse recording for commands
        self._parse_recording()

        session = self.current_session
        self.current_session = None
        self.process = None

        return session

    def _parse_recording(self):
        """Parse recording file for commands"""
        if not self.current_session or not Path(self.current_session.recording_path).exists():
            return

        try:
            if self.use_asciinema:
                # Parse asciicast format
                with open(self.current_session.recording_path) as f:
                    for line in f:
                        try:
                            entry = json.loads(line)
                            if isinstance(entry, list) and len(entry) >= 3:
                                # [time, type, data]
                                if entry[1] == 'o':  # output
                                    self.current_session.commands.append({
                                        'type': 'output',
                                        'data': entry[2],
                                        'time': entry[0],
                                    })
                        except Exception:
                            pass
            else:
                # Parse script/typescript format
                with open(self.current_session.recording_path, 'rb') as f:
                    content = f.read().decode('utf-8', errors='ignore')
                    # Extract commands (lines starting with prompt)
                    lines = content.split('\n')
                    for line in lines:
                        if line.strip() and not line.startswith('\x1b'):  # Skip escape sequences
                            self.current_session.commands.append({
                                'type': 'command',
                                'data': line.strip(),
                            })
        except Exception:
            pass

    def capture_command(self, command: str, output: str = "", cwd: str = None) -> TerminalEvidence:
        """Capture a single command execution"""
        session_name = f"cmd_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
        self.start_recording(session_name)

        # Write command to process
        if self.process and self.process.stdin:
            self.process.stdin.write(f"{command}\n".encode())
            self.process.stdin.flush()

            # Read output (with timeout)
            try:
                import select
                ready, _, _ = select.select([self.process.stdout], [], [], 5)
                if ready:
                    output_data = self.process.stdout.read(4096).decode('utf-8', errors='ignore')
                    output = output_data
            except Exception:
                pass

        return self.stop_recording()

    def get_session_commands(self) -> List[Dict]:
        """Get commands from current session"""
        if self.current_session:
            return self.current_session.commands
        return []


class TerminalRecorder:
    """High-level terminal recorder for exploit evidence"""

    def __init__(self, config_manager=None):
        from core.config_manager import get_config
        self.config = config_manager or get_config()
        self.capture = TerminalCapture(config_manager)

    async def record_exploit_execution(self, exploit_script: str, session_name: str) -> TerminalEvidence:
        """Record exploit script execution"""
        # Create temporary exploit script
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
            f.write(exploit_script)
            script_path = f.name

        try:
            # Make executable
            os.chmod(script_path, 0o755)

            # Start recording
            self.capture.start_recording(session_name)

            # Execute script
            process = await asyncio.create_subprocess_exec(
                "bash", script_path,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=os.path.dirname(script_path),
            )

            # Wait for completion
            stdout, stderr = await process.communicate()

            # Stop recording
            evidence = self.capture.stop_recording()

            # Add output to evidence
            if evidence:
                evidence.commands.append({
                    'type': 'exploit_execution',
                    'script': exploit_script,
                    'stdout': stdout.decode('utf-8', errors='ignore'),
                    'stderr': stderr.decode('utf-8', errors='ignore'),
                    'return_code': process.returncode,
                })

            return evidence

        finally:
            # Cleanup
            Path(script_path).unlink(missing_ok=True)

    async def record_manual_session(self, session_name: str, commands: List[str]) -> TerminalEvidence:
        """Record a manual session with multiple commands"""
        self.capture.start_recording(session_name)

        for cmd in commands:
            # This would need interactive terminal
            # For now, execute sequentially
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            self.capture.current_session.commands.append({
                'type': 'command',
                'command': cmd,
                'stdout': stdout.decode('utf-8', errors='ignore'),
                'stderr': stderr.decode('utf-8', errors='ignore'),
                'return_code': process.returncode,
            })

        return self.capture.stop_recording()

    def get_asciinema_player_html(self, recording_path: str) -> str:
        """Generate HTML for asciinema player"""
        return f'''
<!DOCTYPE html>
<html>
<head>
    <title>Terminal Recording</title>
    <script src="https://cdn.jsdelivr.net/npm/asciinema-player@3/dist/asciinema-player.min.js"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/asciinema-player@3/dist/asciinema-player.css">
</head>
<body>
    <asciinema-player src="{recording_path}" cols="120" rows="30" font-size="14" theme="monokai"></asciinema-player>
</body>
</html>
'''


class CommandCapture:
    """Capture individual commands with full context"""

    def __init__(self, config_manager=None):
        from core.config_manager import get_config
        self.config = config_manager or get_config()
        self.output_dir = Path(self.config.load_validation().terminal.output_dir) / "commands"
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def capture(self, command: str, description: str = "", working_dir: str = None) -> Dict[str, Any]:
        """Capture command execution with full context"""
        import time
        import uuid

        capture_id = str(uuid.uuid4())[:8]
        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')

        # Prepare environment
        env = os.environ.copy()
        env['TERM'] = 'xterm-256color'
        env['COLUMNS'] = '120'
        env['LINES'] = '30'

        start_time = time.time()

        # Execute command
        process = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=working_dir,
            env=env,
        )

        stdout, stderr = await process.communicate()

        end_time = time.time()

        # Build capture record
        record = {
            'id': capture_id,
            'timestamp': datetime.utcnow().isoformat(),
            'command': command,
            'description': description,
            'working_dir': working_dir or os.getcwd(),
            'stdout': stdout.decode('utf-8', errors='ignore'),
            'stderr': stderr.decode('utf-8', errors='ignore'),
            'return_code': process.returncode,
            'duration_seconds': end_time - start_time,
            'environment': {k: v for k, v in env.items() if k in ['PATH', 'HOME', 'USER', 'SHELL']},
        }

        # Save to file
        filename = f"cmd_{timestamp}_{capture_id}.json"
        filepath = self.output_dir / filename

        with open(filepath, 'w') as f:
            json.dump(record, f, indent=2)

        return record

    async def capture_with_script(self, script: str, description: str = "") -> Dict[str, Any]:
        """Capture script execution"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False) as f:
            f.write(script)
            script_path = f.name

        try:
            os.chmod(script_path, 0o755)
            return await self.capture(f"bash {script_path}", description)
        finally:
            Path(script_path).unlink(missing_ok=True)


import json