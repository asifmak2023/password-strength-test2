import streamlit as st
import re
import secrets
import string
import pandas as pd
import altair as alt

# Initialize analytics dictionary to track user interactions
analytics = {
    "password_strength_checks": 0,
    "password_generations": 0,
    "strength_distribution": {"Strong": 0, "Moderate": 0, "Weak": 0},
    "custom_rules_usage": {
        "require_upper": 0,
        "require_lower": 0,
        "require_digit": 0,
        "require_special": 0
    },
    "generated_password_lengths": [],
}

# Function to count character types in a password
def count_character_types(password):
    counts = {
        "Uppercase": len(re.findall(r'[A-Z]', password)),
        "Lowercase": len(re.findall(r'[a-z]', password)),
        "Digits": len(re.findall(r'[0-9]', password)),
        "Special Characters": len(re.findall(r'[!@#$%^&*(),.?\":{}|<>]', password))
    }
    return counts

# Function to check password strength
def check_password_strength(password, min_length=8, require_upper=True, require_lower=True, require_digit=True, require_special=True):
    strength = 0
    feedback = []

    # Count characters
    char_counts = count_character_types(password)

    if len(password) >= min_length:
        strength += 1
    else:
        feedback.append(f"Password should be at least {min_length} characters long.")

    if require_upper and char_counts["Uppercase"] > 0:
        strength += 1
    elif require_upper:
        feedback.append("Password should contain at least one uppercase letter.")

    if require_lower and char_counts["Lowercase"] > 0:
        strength += 1
    elif require_lower:
        feedback.append("Password should contain at least one lowercase letter.")

    if require_digit and char_counts["Digits"] > 0:
        strength += 1
    elif require_digit:
        feedback.append("Password should contain at least one number.")

    if require_special and char_counts["Special Characters"] > 0:
        strength += 1
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

            st.progress(1.0 if strength == "Strong" else 0.66 if strength == "Moderate" else 0.33)

            if feedback:
                st.write("**Feedback:**")
                for item in feedback:
                    st.write(f"- {item}")

            st.write("### Dynamic Character Counts")
            for char_type, count in char_counts.items():
                st.write(f"- **{char_type}:** {count}")

    with tab2:
        st.header("🔑 Generate Strong Password")
        gen_length = st.slider("Password Length", 8, 20, 12)
        include_upper = st.checkbox("Include Uppercase Letters", True)
        include_lower = st.checkbox("Include Lowercase Letters", True)
        include_digits = st.checkbox("Include Digits", True)
        include_special = st.checkbox("Include Special Characters", True)

        if st.button("Generate Password"):
            analytics["password_generations"] += 1
            analytics["generated_password_lengths"].append(gen_length)

            password = generate_password(gen_length, include_upper, include_lower, include_digits, include_special)
            st.write(f"**Generated Password:** `{password}`")

            char_counts = count_character_types(password)

            st.write("### Dynamic Character Counts")
            for char_type, count in char_counts.items():
                st.write(f"- **{char_type}:** {count}")

    # Move Analytics Dashboard to Sidebar
    st.sidebar.header("📊 Analytics Dashboard")

    st.sidebar.subheader("User Interactions")
    st.sidebar.write(f"- **Password Strength Checks:** {analytics['password_strength_checks']}")
    st.sidebar.write(f"- **Password Generations:** {analytics['password_generations']}")

    st.sidebar.subheader("Password Strength Distribution")
    for strength, count in analytics["strength_distribution"].items():
        st.sidebar.write(f"- **{strength}:** {'Yes' if count else 'No'}")

    # Updated Custom Rules Usage
    st.sidebar.subheader("Custom Rules Usage")
    st.sidebar.write(f"- **Require Uppercase:** {'Yes' if char_counts.get('Uppercase', 0) == 0 else 'No'}")
    st.sidebar.write(f"- **Require Lowercase:** {'Yes' if char_counts.get('Lowercase', 0) == 0 else 'No'}")
    st.sidebar.write(f"- **Require Digit:** {'Yes' if char_counts.get('Digits', 0) == 0 else 'No'}")
    st.sidebar.write(f"- **Require Special Character:** {'Yes' if char_counts.get('Special Characters', 0) == 0 else 'No'}")

    if analytics["generated_password_lengths"]:
        avg_length = sum(analytics["generated_password_lengths"]) / len(analytics["generated_password_lengths"])
        st.sidebar.subheader("Generated Password Stats")
        st.sidebar.write(f"- **Average Length:** {avg_length:.2f}")
        st.sidebar.write(f"- **Total Generated:** {len(analytics['generated_password_lengths'])}")

# Run the app
if __name__ == "__main__":
    main()
