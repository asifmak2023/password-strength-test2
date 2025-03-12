import streamlit as st
import re
import secrets
import string
import pandas as pd
import plotly.graph_objects as go

# Initialize analytics
analytics = {
    "password_strength_checks": 0,
    "password_generations": 0,
    "strength_distribution": {"Strong": 0, "Moderate": 0, "Weak": 0},
}

# Function to count character types
def count_character_types(password):
    return {
        "Uppercase": len(re.findall(r'[A-Z]', password)),
        "Lowercase": len(re.findall(r'[a-z]', password)),
        "Digits": len(re.findall(r'[0-9]', password)),
        "Special Characters": len(re.findall(r'[!@#$%^&*(),.?\":{}|<>]', password))
    }

# Function to check password strength
def check_password_strength(password, min_length=8):
    strength = 0
    feedback = []
    char_counts = count_character_types(password)

    if len(password) >= min_length:
        strength += 1
    else:
        feedback.append(f"Password should be at least {min_length} characters long.")

    if char_counts["Uppercase"] > 0:
        strength += 1
    else:
        feedback.append("Include at least one uppercase letter.")

    if char_counts["Lowercase"] > 0:
        strength += 1
    else:
        feedback.append("Include at least one lowercase letter.")

    if char_counts["Digits"] > 0:
        strength += 1
    else:
        feedback.append("Include at least one digit.")

    if char_counts["Special Characters"] > 0:
        strength += 1
    else:
        feedback.append("Include at least one special character.")

    if strength == 5:
        return "Strong", feedback, char_counts, 100
    elif strength >= 3:
        return "Moderate", feedback, char_counts, 50
    else:
        return "Weak", feedback, char_counts, 20

# Function to generate a password
def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

# Function to create a speedometer chart
def create_gauge_chart(value):
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        title={"text": "Password Strength"},
        gauge={
            "axis": {"range": [0, 100]},
            "bar": {"color": "black"},
            "steps": [
                {"range": [0, 30], "color": "red"},
                {"range": [30, 70], "color": "yellow"},
                {"range": [70, 100], "color": "green"}
            ],
        }
    ))
    return fig

# Streamlit app
def main():
    global analytics

    st.title("🔒 Password Strength Meter")
    
    tab1, tab2 = st.tabs(["Check Password Strength", "Generate Strong Password"])
    
    with tab1:
        st.header("🔍 Check Password Strength")
        password = st.text_input("Enter Password", type="password")

        if password:
            analytics["password_strength_checks"] += 1
            strength, feedback, char_counts, gauge_value = check_password_strength(password)
            analytics["strength_distribution"][strength] += 1

            st.write(f"**Strength:** {strength}")

            # Display speedometer gauge chart
            st.plotly_chart(create_gauge_chart(gauge_value))

            if feedback:
                st.write("### ⚠️ Feedback:")
                for item in feedback:
                    st.write(f"- {item}")

    with tab2:
        st.header("🔑 Generate Strong Password")
        gen_length = st.slider("Password Length", 8, 20, 12)

        if st.button("Generate Password"):
            analytics["password_generations"] += 1
            password = generate_password(gen_length)
            st.write(f"**Generated Password:** `{password}`")

    # Sidebar Analytics
    st.sidebar.header("📊 Analytics Dashboard")
    st.sidebar.write(f"- **Password Strength Checks:** {analytics['password_strength_checks']}")
    st.sidebar.write(f"- **Password Generations:** {analytics['password_generations']}")

    st.sidebar.subheader("Password Strength Distribution")
    for strength, count in analytics["strength_distribution"].items():
        st.sidebar.write(f"- **{strength}:** {count}")

if __name__ == "__main__":
    main()
