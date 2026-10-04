import streamlit as st
import streamlit.components.v1 as components
import math
import re
from datetime import datetime

st.set_page_config(
    page_title="Password Strength Analyzer",
    page_icon="🛡️",
    layout="centered"
)

# -------------------- SESSION STATE --------------------
def init_state():
    defaults = {
        "password_input": "",
        "show_password": False,
        "result": None,
        "log": "> Ready for analysis...",
        "breach_result": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_state()

# -------------------- STYLING --------------------
st.markdown("""
<style>
.stApp { background:#0b1018; color:#eeeeee; }
.block-container { max-width:760px; padding-top:1.2rem; padding-bottom:2rem; }
.main-title { text-align:center; color:#00f5a0; font-family:"Courier New",monospace; font-size:42px; font-weight:bold; line-height:1.1; }
.subtitle { text-align:center; color:#a7a7a7; font-family:"Courier New",monospace; font-size:17px; margin-bottom:25px; }
.card { background:#111824; border:2px solid #192231; border-radius:8px; padding:22px; margin:12px 0; }
.section-title { color:#00f5a0; font-family:"Courier New",monospace; font-size:25px; font-weight:bold; margin-bottom:12px; }
.tip { background:#111824; border-left:4px solid #00f5a0; padding:14px; border-radius:5px; color:#eeeeee; }
.console { background:#000000; color:#00f5a0; border-radius:6px; padding:16px; font-family:"Courier New",monospace; white-space:pre-wrap; min-height:80px; }
.analysis-row { display:flex; justify-content:space-between; align-items:center; padding:6px 0; color:#eeeeee; font-family:"Courier New",monospace; font-size:15px; border-bottom:1px solid #192231; }
.check-ok { color:#00f5a0; font-weight:bold; font-size:20px; }
.check-no { color:#ff4040; font-weight:bold; font-size:20px; }
.strength-label { text-align:center; color:#00f5a0; font-family:"Courier New",monospace; font-size:28px; font-weight:bold; margin-top:8px; }
</style>
""", unsafe_allow_html=True)

# -------------------- PASSWORD LOGIC --------------------
def has_sequential_pattern(password):
    value = password.lower()
    for i in range(len(value) - 2):
        a, b, c = ord(value[i]), ord(value[i + 1]), ord(value[i + 2])
        if b == a + 1 and c == b + 1:
            return True
        if b == a - 1 and c == b - 1:
            return True
    return False


def calculate_crack_time(entropy):
    if entropy <= 0:
        return "--"
    guesses = 2 ** entropy
    seconds = guesses / 1000000000
    if seconds < 1:
        return "< 1 sec"
    if seconds < 60:
        return f"{seconds:.1f} sec"
    if seconds < 3600:
        return f"{seconds / 60:.1f} min"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    if seconds < 31536000:
        return f"{seconds / 86400:.1f} days"
    if seconds < 3153600000:
        return f"{seconds / 31536000:.1f} years"
    return "Centuries+"


def analyze_password(password):
    uppercase = bool(re.search(r"[A-Z]", password))
    lowercase = bool(re.search(r"[a-z]", password))
    numbers = bool(re.search(r"[0-9]", password))
    symbols = bool(re.search(r"[^A-Za-z0-9]", password))
    repeated = bool(re.search(r"(.)\1{2,}", password))
    sequential = has_sequential_pattern(password)

    pool = 0
    if uppercase: pool += 26
    if lowercase: pool += 26
    if numbers: pool += 10
    if symbols: pool += 33

    entropy = len(password) * math.log2(pool) if pool > 0 else 0

    score = 0
    if len(password) >= 8: score += 20
    if len(password) >= 12: score += 15
    if len(password) >= 16: score += 10
    if uppercase: score += 10
    if lowercase: score += 10
    if numbers: score += 10
    if symbols: score += 15
    if not repeated: score += 5
    if not sequential: score += 5
    if repeated: score -= 15
    if sequential: score -= 15
    score = max(0, min(100, score))

    if score < 30:
        strength = "Weak"
    elif score < 55:
        strength = "Medium"
    elif score < 80:
        strength = "Strong"
    else:
        strength = "Very Strong"

    suggestions = []
    if len(password) < 12: suggestions.append("Use at least 12 characters.")
    if not uppercase: suggestions.append("Add uppercase letters.")
    if not lowercase: suggestions.append("Add lowercase letters.")
    if not numbers: suggestions.append("Add numbers.")
    if not symbols: suggestions.append("Add special symbols.")
    if repeated: suggestions.append("Avoid repeated characters.")
    if sequential: suggestions.append("Avoid sequential patterns such as abc or 123.")
    if not suggestions: suggestions.append("Excellent! Your password satisfies the main checks.")

    return {
        "uppercase": uppercase,
        "lowercase": lowercase,
        "numbers": numbers,
        "symbols": symbols,
        "repeated": not repeated,
        "sequential": not sequential,
        "score": score,
        "entropy": entropy,
        "crack_time": calculate_crack_time(entropy),
        "strength": strength,
        "length": len(password),
        "suggestions": suggestions,
    }


def breach_check(password):
    common_passwords = {
        "password", "123456", "12345678", "qwerty", "password123",
        "admin", "welcome", "letmein", "abc123", "iloveyou"
    }
    return password.lower() in common_passwords


def create_report(result):
    return f"""PASSWORD SECURITY ANALYSIS REPORT
==================================

Date:
{datetime.now().strftime('%d-%m-%Y %H:%M:%S')}

Password Length:
{result['length']}

Strength:
{result['strength']}

Score:
{result['score']}%

Entropy:
{result['entropy']:.2f} Bits

Estimated Crack Time:
{result['crack_time']}

Security Recommendation:
Use a unique password with sufficient length,
mixed character types and avoid predictable patterns.

Privacy Note:
The actual password is not included in this report.
"""

# -------------------- CALLBACKS --------------------
def clear_password():
    st.session_state.password_input = ""
    st.session_state.result = None
    st.session_state.breach_result = None
    st.session_state.show_password = False
    st.session_state.log = "> Password cleared ✔"


def reset_all():
    st.session_state.password_input = ""
    st.session_state.result = None
    st.session_state.breach_result = None
    st.session_state.show_password = False
    st.session_state.log = "> All data reset ✔\n> Ready for analysis..."


def toggle_show():
    st.session_state.show_password = not st.session_state.show_password


def check_password():
    password = st.session_state.password_input
    if not password:
        st.session_state.log = "> Please enter a password first."
        return
    r = analyze_password(password)
    st.session_state.result = r
    st.session_state.log = (
        "> Password analyzed ✔\n"
        f"> Strength: {r['strength']}\n"
        f"> Score: {r['score']}%\n"
        f"> Entropy: {r['entropy']:.1f} Bits"
    )


def run_breach_check():
    password = st.session_state.password_input
    if not password:
        st.session_state.breach_result = "empty"
        st.session_state.log = "> Enter a password first."
    elif breach_check(password):
        st.session_state.breach_result = "common"
        st.session_state.log = "> Breach check completed\n> ⚠ Common password detected"
    else:
        st.session_state.breach_result = "not_found"
        st.session_state.log = "> Breach check completed\n> No local common-password match ✔"

# -------------------- HEADER --------------------
st.markdown('<div style="text-align:center;font-size:55px;">🛡</div>', unsafe_allow_html=True)
st.markdown('<div class="main-title">Password<br>Strength Analyzer</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">Cyber Security Project</div>', unsafe_allow_html=True)

# -------------------- INPUT CARD --------------------
st.markdown('<div class="card">', unsafe_allow_html=True)
st.markdown('<div class="section-title">🔴  🟡  🟢 &nbsp;&nbsp; Terminal</div>', unsafe_allow_html=True)

st.text_input(
    "🔑 Password",
    key="password_input",
    type="default" if st.session_state.show_password else "password",
    placeholder="Enter a password to analyze"
)

c1, c2 = st.columns(2)
with c1:
    st.button("🔐  Check Password", use_container_width=True, type="primary", on_click=check_password)
with c2:
    show_text = "🙈  Hide" if st.session_state.show_password else "👁  Show"
    st.button(show_text, use_container_width=True, on_click=toggle_show)

c3, c4 = st.columns(2)
with c3:
    st.button("📋  Copy", use_container_width=True, on_click=None)
with c4:
    st.button("🗑  Clear", use_container_width=True, on_click=clear_password)

st.button("🐞  Breach Check", use_container_width=True, on_click=run_breach_check)
st.markdown('</div>', unsafe_allow_html=True)

# Copy button is rendered separately so browser clipboard can be used without storing the password server-side.
if st.session_state.password_input:
    safe_password = st.session_state.password_input.replace('\\', '\\\\').replace('`', '\\`').replace('${', '\\${')
    st.markdown("<div style='height:0;overflow:hidden'>", unsafe_allow_html=True)
    components.html(f"""
    <script>
    const parent = window.parent.document;
    const buttons = Array.from(parent.querySelectorAll('button')).filter(b => b.innerText.includes('📋'));
    buttons.forEach(btn => {{
        btn.onclick = async () => {{
            try {{
                await navigator.clipboard.writeText(`{safe_password}`);
            }} catch(e) {{
                const area = document.createElement('textarea');
                area.value = `{safe_password}`;
                document.body.appendChild(area);
                area.select();
                document.execCommand('copy');
                area.remove();
            }}
        }};
    }});
    </script>
    """, height=0)
    st.markdown("</div>", unsafe_allow_html=True)

# -------------------- BREACH MESSAGE --------------------
breach_result = st.session_state.breach_result
if breach_result == "empty":
    st.warning("Enter a password first.")
elif breach_result == "common":
    st.warning("⚠️ Warning: This password appears in the local common-password list.")
elif breach_result == "not_found":
    st.info("No match found in the local common-password list.")

# -------------------- RESULTS --------------------
result = st.session_state.result
if result:
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="section-title">Password Strength</div>', unsafe_allow_html=True)
    st.progress(result["score"] / 100)
    st.markdown(f'<div class="strength-label">{result["strength"]}</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="section-title">Security Details</div>', unsafe_allow_html=True)
    a, b = st.columns(2)
    with a:
        st.metric("Score", f'{result["score"]}%')
        st.metric("Entropy", f'{result["entropy"]:.1f} Bits')
    with b:
        st.metric("Crack Time", result["crack_time"])
        st.metric("Password Length", result["length"])
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="section-title">Suggestions</div>', unsafe_allow_html=True)
    for item in result["suggestions"]:
        st.markdown(f"💡 {item}")
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="section-title">Security Tip</div>', unsafe_allow_html=True)
    st.markdown('<div class="tip">Use unique passwords. Avoid names, birthdays, common words and predictable patterns.</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="section-title">Console</div>', unsafe_allow_html=True)
    st.markdown(f'<div class="console">{st.session_state.log}</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="section-title">Password Analysis</div>', unsafe_allow_html=True)
    checks = [
        ("Uppercase", result["uppercase"]),
        ("Lowercase", result["lowercase"]),
        ("Numbers", result["numbers"]),
        ("Symbols", result["symbols"]),
        ("Repeated Characters", result["repeated"]),
        ("Sequential Pattern", result["sequential"]),
    ]
    for label, passed in checks:
        icon = "✓" if passed else "✕"
        cls = "check-ok" if passed else "check-no"
        st.markdown(f'<div class="analysis-row"><span>{label}</span><span class="{cls}">{icon}</span></div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

    st.download_button(
        "📄  Export Report",
        data=create_report(result),
        file_name="password_security_report.txt",
        mime="text/plain",
        use_container_width=True,
        type="primary"
    )
else:
    # Keep the console visible even before the first analysis.
    st.markdown('<div class="card">', unsafe_allow_html=True)
    st.markdown('<div class="section-title">Console</div>', unsafe_allow_html=True)
    st.markdown(f'<div class="console">{st.session_state.log}</div>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)

# -------------------- RESET --------------------
st.button("🔄  Reset", use_container_width=True, type="primary", on_click=reset_all)

st.markdown(
    '<div style="text-align:center;color:#a7a7a7;font-family:Courier New,monospace;margin-top:25px;">'
    '© 2026 Password Strength Analyzer<br>Developed for Cyber Security Project</div>',
    unsafe_allow_html=True
)
