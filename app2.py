import streamlit as st
import re
import secrets
import string
import pandas as pd
import altair as alt
import plotly.graph_objects as go

# Initialize analytics dictionary
analytics = {
    "password_strength_checks": 0,
    "password_generations": 0,
    "strength_distribution": {"Strong": 0, "Moderate": 0, "Weak": 0},
    "generated_password_lengths": [],
    "custom_rules_usage": {"require_upper": 0, "require_lower": 0, "require_digit": 0, "require_special": 0},
}

# Function to count character types in a password
def count_character_types(password):
    return {
        "Uppercase": len(re.findall(r'[A-Z]', password)),
        "Lowercase": len(re.findall(r'[a-z]', password)),
        "Digits": len(re.findall(r'[0-9]', password)),
        "Special Characters": len(re.findall(r'[!@#$%^&*(),.?\":{}|<>]', password))
    }

# Function to check password strength
def check_password_strength(password, min_length=8, require_upper=True, require_lower=True, require_digit=True, require_special=True):
    strength = 0
    feedback = []
    char_counts = count_character_types(password)

    if len(password) >= min_length:
        strength += 1
    else:
        feedback.append(f"Password should be at least {min_length} characters long.")

    if require_upper and char_counts["Uppercase"] > 0:
        strength += 1
        analytics["custom_rules_usage"]["require_upper"] += 1
    elif require_upper:
        feedback.append("Password should contain at least one uppercase letter.")

    if require_lower and char_counts["Lowercase"] > 0:
        strength += 1
        analytics["custom_rules_usage"]["require_lower"] += 1
    elif require_lower:
        feedback.append("Password should contain at least one lowercase letter.")

    if require_digit and char_counts["Digits"] > 0:
        strength += 1
        analytics["custom_rules_usage"]["require_digit"] += 1
    elif require_digit:
        feedback.append("Password should contain at least one number.")

    if require_special and char_counts["Special Characters"] > 0:
        strength += 1
        analytics["custom_rules_usage"]["require_special"] += 1
    elif require_special:
        feedback.append("Password should contain at least one special character.")

    if strength == 5:
        return "Strong", feedback, char_counts
    elif strength >= 3:
        return "Moderate", feedback, char_counts
    else:
        return "Weak", feedback, char_counts

# Function to generate a strong password
def generate_password(length=12, include_upper=True, include_lower=True, include_digits=True, include_special=True):
    characters = "".join([
        string.ascii_uppercase if include_upper else "",
        string.ascii_lowercase if include_lower else "",
        string.digits if include_digits else "",
        string.punctuation if include_special else "",
    ])
    return ''.join(secrets.choice(characters) for _ in range(length)) if characters else "No characters selected."

# Function to visualize character counts
def visualize_character_counts(char_counts):
    char_counts_data = pd.DataFrame({"Character Type": list(char_counts.keys()), "Count": list(char_counts.values())})

    char_chart = alt.Chart(char_counts_data).mark_bar().encode(
        x=alt.X("Character Type:N", title="Character Type"),
        y=alt.Y("Count:Q", title="Count"),
        color=alt.Color("Character Type:N", legend=None),
        tooltip=["Character Type", "Count"]
    ).properties(width=400, height=300, title="Character Count Visualization")

    return char_chart

# Function to create a speedometer chart
def show_speedometer(strength):
    categories = {"Weak": 1, "Moderate": 2, "Strong": 3}
    value = categories.get(strength, 1)

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        title={"text": "Password Strength"},
        gauge={
            "axis": {"range": [0, 3], "tickvals": [1, 2, 3], "ticktext": ["Weak", "Moderate", "Strong"]},
            "bar": {"color": "black"},
            "steps": [
                {"range": [0, 1], "color": "red"},
                {"range": [1, 2], "color": "yellow"},
                {"range": [2, 3], "color": "green"},
            ]
        }
    ))
    
    return fig

# Streamlit app
def main():
    global analytics

    st.title("🔒 Password Strength Meter")
    st.write("Check the strength of your password or generate a strong one.")

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

    tab1, tab2 = st.tabs(["Check Password Strength", "Generate Strong Password"])

    char_counts = {}

    with tab1:
        st.header("🔍 Check Password Strength")
        password = st.text_input("Enter Password", type="password")

        if password:
            analytics["password_strength_checks"] += 1
            strength, feedback, char_counts = check_password_strength(
                password, min_length, require_upper, require_lower, require_digit, require_special
            )
            analytics["strength_distribution"][strength] += 1

            color = {"Strong": "🟢", "Moderate": "🟡", "Weak": "🔴"}[strength]
            st.write(f"**Strength:** {color} {strength}")

            # Display both graphs side by side
            col1, col2 = st.columns(2)
            with col1:
                st.plotly_chart(show_speedometer(strength), use_container_width=True, key="strength_meter_input")
            with col2:
                st.altair_chart(visualize_character_counts(char_counts), use_container_width=True)

            if feedback:
                st.write("**Feedback:**")
                for item in feedback:
                    st.write(f"- {item}")

    with tab2:
        st.header("🔑 Generate Strong Password")
        gen_length = st.slider("Password Length", 8, 20, 12)

        if st.button("Generate Password"):
            analytics["password_generations"] += 1
            analytics["generated_password_lengths"].append(gen_length)

            password = generate_password(gen_length, require_upper, require_lower, require_digit, require_special)
            st.write(f"**Generated Password:** `{password}`")

            char_counts = count_character_types(password)

            # Display both graphs side by side
            col1, col2 = st.columns(2)
            with col1:
                st.plotly_chart(show_speedometer("Moderate"), use_container_width=True, key="strength_meter_generated")
            with col2:
                st.altair_chart(visualize_character_counts(char_counts), use_container_width=True)

    # Sidebar Analytics
    st.sidebar.header("📊 Analytics Dashboard")
    st.sidebar.subheader("Custom Rule Usage")
    for rule, count in analytics["custom_rules_usage"].items():
        st.sidebar.write(f"- **{rule.replace('_', ' ').title()}**: {count}")

    if analytics["generated_password_lengths"]:
        avg_length = sum(analytics["generated_password_lengths"]) / len(analytics["generated_password_lengths"])
        st.sidebar.subheader("Generated Password Stats")
        st.sidebar.write(f"- **Average Length:** {avg_length:.2f}")
        st.sidebar.write(f"- **Total Generated:** {len(analytics['generated_password_lengths'])}")

# Run the app
if __name__ == "__main__":
    main()
