import os
import json
import zipfile
import io
import requests
import subprocess
import tempfile
from typing import List
from pydantic import BaseModel, Field
from google import genai
from google.genai import types

# 1. بنية البيانات
class FileVulnerability(BaseModel):
    file_path: str = Field(description="Relative path of the file containing the flaw")
    vulnerability_type: str = Field(description="e.g., SQL Injection, Command Injection, Memory Leak, Hardcoded Secret")
    severity: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW")
    vulnerable_line: str = Field(description="Exact problematic line or block of code")
    explanation: str = Field(description="Technical reason why this code is vulnerable")
    patched_code: str = Field(description="Fixed secure version of the code block")
    unit_test: str = Field(description="Executable Python unit test to verify the patch")

class RepositoryAuditReport(BaseModel):
    overall_security_score: int = Field(description="Score out of 100 based on security posture")
    summary: str = Field(description="High-level assessment summary of the code repository")
    total_files_analyzed: int = Field(description="Count of files parsed")
    vulnerabilities: List[FileVulnerability] = Field(default_factory=list)
ALLOWED_EXTENSIONS = {'.py', '.js', '.ts', '.jsx', '.tsx', '.cpp', '.c', '.h', '.java', '.go', '.php', '.rs', '.sql', '.html', '.sh'}
IGNORE_DIRS = {'node_modules', '.git', 'venv', '_pycache_', 'dist', 'build'}

# --- الميزة الأولى: تحميل GitHub Repo عبر URL ---
def fetch_github_repo_zip(repo_url: str) -> bytes:
    clean_url = repo_url.rstrip('/').replace('.git', '')
    parts = clean_url.split('/')
    if len(parts) < 5 or 'github.com' not in parts[2]:
        raise ValueError("رابط GitHub غير صحيح. استعمل الصيغة: https://github.com/username/repository")
    
    owner, repo = parts[3], parts[4]
    
    # تجربة الفروع الأساسية (main / master)
    for branch in ['main', 'master']:
        zip_url = f"https://github.com/{owner}/{repo}/archive/refs/heads/{branch}.zip"
        res = requests.get(zip_url, timeout=15)
        if res.status_code == 200:
            return res.content
            
    # API Fallback
    api_url = f"https://api.github.com/repos/{owner}/{repo}/zipball"
    res = requests.get(api_url, timeout=15)
    if res.status_code == 200:
        return res.content
        
    raise Exception("فشل تحميل Repository. تأكد من أن المستودع عام (Public).")

def extract_code_from_zip(zip_bytes: bytes) -> dict:
    files_content = {}
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as z:
        for file_info in z.infolist():
            if file_info.is_dir():
                continue
            path_parts = file_info.filename.split('/')
            if any(part in IGNORE_DIRS for part in path_parts):
                continue
                
            _, ext = os.path.splitext(file_info.filename)
            if ext.lower() in ALLOWED_EXTENSIONS:
                try:
                    content = z.read(file_info.filename).decode('utf-8', errors='ignore')
                    files_content[file_info.filename] = content
                except Exception:
                    pass
    return files_content

# --- الميزة الثانية: محرك تشغيل واختبار الـ Unit Test محلياً ---
def execute_verification_test(patched_code: str, unit_test: str) -> dict:
    combined_script = f"""
# --- GENERATED PATCH ---
{patched_code}

# --- AUTOMATED TEST ---
{unit_test}
"""
    with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
        f.write(combined_script)
        temp_path = f.name

    try:
        result = subprocess.run(
            ['python3', temp_path],
            capture_output=True,
            text=True,
            timeout=5
        )
        passed = (result.returncode == 0)
        output = result.stdout if passed else result.stderr
        return {
            "passed": passed,
            "output": output.strip() if output else ("Test passed with 0 errors" if passed else "Execution failed")
        }
    except subprocess.TimeoutExpired:
        return {"passed": False, "output": "Timeout Error: Test execution exceeded 5s limit."}
    except Exception as e:
        return {"passed": False, "output": f"Execution Exception: {str(e)}"}
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

def analyze_repository(files_map: dict) -> dict:
    formatted_repo = ""
    for path, code in files_map.items():
        formatted_repo += f"\n--- FILE: {path} ---\n{code}\n"
        
    prompt = f"""
    You are SentinelCode AI, an elite DevSecOps Agent.
    Perform an in-depth security audit on this codebase for OWASP vulnerabilities and code flaws.

    Repository Files:
    {formatted_repo}

    Respond ONLY in valid JSON matching the schema. Always include runnable Python unit tests for patches where applicable.
    """
    
    response = client.models.generate_content(
        model="gemini-2.5-flash",
        contents=prompt,
        config=types.GenerateContentConfig(
            response_mime_type="application/json",
            response_schema=RepositoryAuditReport,
            temperature=0.1,
        ),
    )
    return json.loads(response.text)

def analyze_single_snippet(code: str, language: str = "python") -> dict:
    return analyze_repository({f"snippet.{language}": code})