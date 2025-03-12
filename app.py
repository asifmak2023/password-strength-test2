import streamlit as st
import re
import secrets
import string
import pandas as pd
import altair as alt

# Initialize analytics dictionary
analytics = {
    "password_strength_checks": 0,
    "password_generations": 0,
    "strength_distribution": {"Strong": 0, "Moderate": 0, "Weak": 0},
    "custom_rules_usage": {"require_upper": 0, "require_lower": 0, "require_digit": 0, "require_special": 0},
    "generated_password_lengths": []
}

st.markdown(
    """
    <style>
    .main > div { padding-left: 0rem; padding-right: 0rem; }
    </style>
    """,
    unsafe_allow_html=True
)

def check_password_strength(password, min_length=8, **rules):
    feedback = []
    strength = sum([
        len(password) >= min_length or feedback.append(f"At least {min_length} characters required."),
        bool(re.search(r'[A-Z]', password)) if rules["require_upper"] else True or feedback.append("Include an uppercase letter."),
        bool(re.search(r'[a-z]', password)) if rules["require_lower"] else True or feedback.append("Include a lowercase letter."),
        bool(re.search(r'[0-9]', password)) if rules["require_digit"] else True or feedback.append("Include a number."),
        bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)) if rules["require_special"] else True or feedback.append("Include a special character.")
    ])
    return ("Strong" if strength == 5 else "Moderate" if strength >= 3 else "Weak"), feedback

def generate_password(length=12, **rules):
    character_sets = {
        "require_upper": string.ascii_uppercase,
        "require_lower": string.ascii_lowercase,
        "require_digit": string.digits,
        "require_special": string.punctuation
    }
    characters = "".join(value for key, value in character_sets.items() if rules[key])
    return "No characters selected." if not characters else "".join(secrets.choice(characters) for _ in range(length))

def visualize_character_counts(password):
    char_counts = {
        "Uppercase": len(re.findall(r'[A-Z]', password)),
        "Lowercase": len(re.findall(r'[a-z]', password)),
        "Digits": len(re.findall(r'[0-9]', password)),
        "Special Characters": len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', password))
    }
    df = pd.DataFrame(list(char_counts.items()), columns=["Character Type", "Count"])
    st.altair_chart(
        alt.Chart(df).mark_bar().encode(
            x=alt.X("Character Type", title="Character Type"),
            y=alt.Y("Count", title="Count"),
            color="Character Type",
            tooltip=["Character Type", "Count"]
        ).properties(width=600, height=300, title="Character Count Visualization"),
        use_container_width=True
    )

def main():
    global analytics
    st.title("Password Strength Meter")
    st.write("Check password strength or generate a strong one.")
    st.header("Customize Password Rules")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        min_length = st.slider("Minimum Length", 6, 20, 8)
    with col2:
        require_upper = st.checkbox("Require Uppercase Letters", True)
        require_lower = st.checkbox("Require Lowercase Letters", True)
    with col3:
        require_digit = st.checkbox("Require Digits", True)
        require_special = st.checkbox("Require Special Characters", True)
    
    rules = {"require_upper": require_upper, "require_lower": require_lower, "require_digit": require_digit, "require_special": require_special}
    tab1, tab2 = st.tabs(["Check Password Strength", "Generate Strong Password"])
    
    with tab1:
        st.header("Check Password Strength")
        password = st.text_input("Enter Password", type="password")
        if password:
            
            analytics["password_strength_checks"] += 1
            strength, feedback = check_password_strength(password, min_length, **rules)
            analytics["strength_distribution"][strength] += 1
            
            st.write(f"**Strength:** {strength}")
            st.progress({"Strong": 1.0, "Moderate": 0.66, "Weak": 0.33}[strength])
            if feedback:
                st.write("**Feedback:**")
                for fb in feedback:
                    st.write(f"- {fb}")
            st.write("### Character Counts")
            visualize_character_counts(password)
    
    with tab2:
        st.header("Generate Strong Password")
        gen_length = st.slider("Password Length", 8, 20, 12)
        if st.button("Generate Password"):
            analytics["password_generations"] += 1
            analytics["generated_password_lengths"].append(gen_length)
            for key in rules:
                analytics["custom_rules_usage"][key] += int(rules[key])
            password = generate_password(gen_length, **rules)
            st.write(f"**Generated Password:** `{password}`")
            st.write("### Character Counts")
            visualize_character_counts(password)
    
    st.header("Analytics Dashboard")
    col_a, col_b, col_c = st.columns(3)
    with col_a:
        st.write(f"**Password Strength Checks:** {analytics['password_strength_checks']}")
        st.write(f"**Password Generations:** {analytics['password_generations']}")
    with col_b:
        for k, v in analytics["strength_distribution"].items():
            st.write(f"**{k}:** {v}")
    with col_c:
        for k, v in analytics["custom_rules_usage"].items():
            st.write(f"**{k.replace('_', ' ').title()}:** {v}")
        if analytics["generated_password_lengths"]:
            avg_length = sum(analytics["generated_password_lengths"]) / len(analytics["generated_password_lengths"])
            st.write(f"**Avg. Generated Length:** {avg_length:.2f}")
            st.write(f"**Total Generated:** {len(analytics['generated_password_lengths'])}")

if __name__ == "__main__":
    main()