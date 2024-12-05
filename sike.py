import re


# Load the external dictionary file
def load_dictionary():
    try:
        with open("dictionary.txt", "r") as file:
            dictionary_words = [line.strip().lower() for line in file.readlines()]
        return dictionary_words
    except FileNotFoundError:
        print("Dictionary file not found, using fallback small list.")
        return [
            "apple", "banana", "cherry", "dog", "cat", "house", "computer", "laptop", "password", "sunshine",
            "princess", "football", "qwerty", "hello", "welcome", "admin", "superman", "letmein", "iloveyou"
        ]


# Sample common password variations (can be extended)
common_password_variations = [
    "password1", "letmein", "admin123", "qwerty123", "12345678", "1234abcd", "123qwerty", "password123",
    "welcome123", "iloveyou2024", "12345password", "123qwerty"
]


# Function to check if password contains any dictionary word
def contains_dictionary_word(password, dictionary_words):
    for word in dictionary_words:
        if word in password.lower():
            return True
    return False


# Function to check for keyboard patterns (e.g., "qwerty", "asdfgh")
def contains_keyboard_pattern(password):
    keyboard_patterns = ["qwerty", "asdfgh", "zxcvbn", "qwertyu", "asdfg", "qwertyuiop"]
    for pattern in keyboard_patterns:
        if pattern in password.lower():
            return True
    return False


# Function to check for repetitive characters (e.g., "aaaa", "1111")
def contains_repeated_characters(password):
    return bool(re.search(r"(.)\1\1", password))


# Function to check for common password variations (e.g., "password1", "admin123")
def contains_common_variation(password):
    for variation in common_password_variations:
        if variation in password.lower():
            return True
    return False


# Function to check for sequences (e.g., "1234", "abcd")
def contains_sequence(password):
    # Numeric sequence patterns
    if re.search(r"1234|2345|3456|4567|5678|6789|7890", password):
        return True
    # Alphabetic sequence patterns (e.g., "abcd")
    if re.search(r"abcd|bcde|cdef|defg|efgh|fghi|ghij", password.lower()):
        return True
    return False


# Function to check password strength with score
def password_strength(password):
    # Load dictionary for checking words
    dictionary_words = load_dictionary()

    score = 0
    feedback = []

    # Check password length
    if len(password) >= 12:
        score += 1
    else:
        feedback.append("Password must be at least 12 characters long.")

    # Check if the password has at least one lowercase letter
    if re.search(r'[a-z]', password):
        score += 1

    # Check if the password has at least one uppercase letter
    if re.search(r'[A-Z]', password):
        score += 1

    # Check if the password has at least one digit
    if re.search(r'[0-9]', password):
        score += 1

    # Check if the password has at least one special character
    if re.search(r'[@$!%*?&]', password):
        score += 1

    # Check if password is too common
    if contains_common_variation(password):
        feedback.append("This is a common password variation, please choose another.")

    # Check if password contains dictionary words
    if contains_dictionary_word(password, dictionary_words):
        feedback.append("Avoid using dictionary words.")

    # Check for keyboard patterns
    if contains_keyboard_pattern(password):
        feedback.append("Avoid using common keyboard patterns like 'qwerty'.")

    # Check if password contains simple sequences
    if contains_sequence(password):
        feedback.append("Avoid using simple sequences like '1234' or 'abcd'.")

    # Check if password contains repeated characters
    if contains_repeated_characters(password):
        feedback.append("Avoid using repeated characters (e.g., 'aaa', '111').")

    # Assign strength based on score
    if score == 6:
        strength = "Very strong password"
    elif score == 5:
        strength = "Strong password"
    elif score == 4:
        strength = "Good password"
    elif score == 3:
        strength = "Fair password"
    elif score == 2:
        strength = "Weak password"
    else:
        strength = "Very weak password"

    return strength, feedback


# Main function to get user input and check the password
def main():
    print("Password Strength Analyzer")
    password = input("Enter a password to analyze: ")

    # Analyze the password and provide feedback
    strength, feedback = password_strength(password)

    print(f"Password Strength: {strength}")

    # Print any additional feedback
    if feedback:
        for comment in feedback:
            print(f"- {comment}")


# Run the main function
if __name__ == "__main__":
    main()