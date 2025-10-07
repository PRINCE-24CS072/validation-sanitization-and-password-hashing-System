<?php
session_start();

// Database connection
$db_host = 'localhost';
$db_user = 'root';
$db_pass = '';
$db_name = 'event_portal';

$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Validation functions
function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

function validatePassword($password) {
    // At least 8 chars, 1 uppercase, 1 lowercase, 1 number
    return strlen($password) >= 8 
           && preg_match('/[A-Z]/', $password)
           && preg_match('/[a-z]/', $password)
           && preg_match('/[0-9]/', $password);
}

// Sanitization function
function sanitizeInput($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data);
    return $data;
}

$errors = [];
$message = "";

// Registration
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST["register"])) {
    $username = sanitizeInput($_POST["username"] ?? "");
    $email = sanitizeInput($_POST["email"] ?? "");
    $password = $_POST["password"] ?? "";
    $confirm_password = $_POST["confirm_password"] ?? "";

    // Validation
    if (empty($username)) {
        $errors[] = "Username is required";
    } elseif (strlen($username) < 3) {
        $errors[] = "Username must be at least 3 characters";
    }

    if (empty($email)) {
        $errors[] = "Email is required";
    } elseif (!validateEmail($email)) {
        $errors[] = "Invalid email format";
    }

    if (empty($password)) {
        $errors[] = "Password is required";
    } elseif (!validatePassword($password)) {
        $errors[] = "Password must be at least 8 characters and contain uppercase, lowercase, and numbers";
    }

    if ($password !== $confirm_password) {
        $errors[] = "Passwords do not match";
    }

    // Check if username/email already exists
    $stmt = $conn->prepare("SELECT id FROM users WHERE username = ? OR email = ?");
    $stmt->bind_param("ss", $username, $email);
    $stmt->execute();
    if ($stmt->get_result()->num_rows > 0) {
        $errors[] = "Username or email already exists";
    }
    $stmt->close();

    // If no errors, proceed with registration
    if (empty($errors)) {
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $username, $email, $hashed_password);
        if ($stmt->execute()) {
            $message = "Registration successful!";
        } else {
            $errors[] = "Registration failed";
        }
        $stmt->close();
    }
}

// Login
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST["login"])) {
    $username = sanitizeInput($_POST["username"] ?? "");
    $password = $_POST["password"] ?? "";

    if (empty($username) || empty($password)) {
        $errors[] = "Both username and password are required";
    } else {
        $stmt = $conn->prepare("SELECT id, username, password FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($user = $result->fetch_assoc()) {
            if (password_verify($password, $user['password'])) {
                $_SESSION['user_id'] = $user['id'];
                $_SESSION['username'] = $user['username'];
                header("Location: dashboard.php");
                exit;
            } else {
                $errors[] = "Invalid password";
            }
        } else {
            $errors[] = "User not found";
        }
        $stmt->close();
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>User Authentication</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f7fafd; }
        .container { max-width: 400px; margin: 40px auto; background: #fff; padding: 32px; border-radius: 12px; box-shadow: 0 4px 16px #ccc; }
        h2 { text-align: center; color: #2980b9; }
        .error { color: #e74c3c; margin-bottom: 10px; }
        .success { color: #27ae60; margin-bottom: 10px; }
        label { display: block; margin-top: 16px; }
        input { width: 100%; padding: 8px; margin-top: 6px; border: 1px solid #bfc9d2; border-radius: 6px; }
        button { width: 100%; padding: 10px; margin-top: 20px; background: #2980b9; color: #fff; border: none; border-radius: 6px; cursor: pointer; }
        .toggle { text-align: center; margin-top: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <?php if (!empty($errors)): ?>
            <?php foreach ($errors as $error): ?>
                <div class="error"><?php echo htmlspecialchars($error); ?></div>
            <?php endforeach; ?>
        <?php endif; ?>

        <?php if ($message): ?>
            <div class="success"><?php echo htmlspecialchars($message); ?></div>
        <?php endif; ?>

        <form method="post" autocomplete="off">
            <h2>Register</h2>
            <label>Username:
                <input type="text" name="username" pattern=".{3,}" title="3 characters minimum">
            </label>
            <label>Email:
                <input type="email" name="email">
            </label>
            <label>Password:
                <input type="password" name="password" pattern="(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}" 
                       title="Must contain at least one number, one uppercase and lowercase letter, and be at least 8 characters long">
            </label>
            <label>Confirm Password:
                <input type="password" name="confirm_password">
            </label>
            <button type="submit" name="register">Register</button>
        </form>

        <form method="post" autocomplete="off" style="margin-top: 40px;">
            <h2>Login</h2>
            <label>Username:
                <input type="text" name="username">
            </label>
            <label>Password:
                <input type="password" name="password">
            </label>
            <button type="submit" name="login">Login</button>
        </form>
    </div>
</body>
</html>
