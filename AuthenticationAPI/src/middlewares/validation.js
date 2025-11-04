const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};

const validatePassword = (password) => {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    
    return {
        isValid: password.length >= minLength && hasUpperCase && hasLowerCase && hasNumber && hasSpecialChar,
        errors: {
            minLength: password.length < minLength,
            hasUpperCase: !hasUpperCase,
            hasLowerCase: !hasLowerCase,
            hasNumber: !hasNumber,
            hasSpecialChar: !hasSpecialChar
        }
    };
};

const validateName = (name) => {
    const nameRegex = /^[a-zA-Z\s]{2,50}$/;
    return nameRegex.test(name);
};

const sanitizeInput = (input) => {
    return input.trim().replace(/[<>]/g, '');
};

module.exports = {
    validateEmail,
    validatePassword,
    validateName,
    sanitizeInput
};