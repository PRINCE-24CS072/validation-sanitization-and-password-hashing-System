<?php
session_start();

// Check if user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: index.php");
    exit;
}

// Database connection
$db_host = 'localhost';
$db_user = 'root';
$db_pass = '';
$db_name = 'event_portal';

$conn = new mysqli($db_host, $db_user, $db_pass, $db_name);
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Fetch user data
$user_id = $_SESSION['user_id'];
$stmt = $conn->prepare("SELECT username, email FROM users WHERE id = ?");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$user = $stmt->get_result()->fetch_assoc();
$stmt->close();
?>

<!DOCTYPE html>
<html>
<head>
    <title>Dashboard</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            background: #f7fafd; 
            margin: 0;
            padding: 20px;
        }
        .container { 
            max-width: 800px; 
            margin: 40px auto; 
            background: #fff; 
            padding: 32px; 
            border-radius: 12px; 
            box-shadow: 0 4px 16px #ccc; 
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
        }
        h2 { 
            color: #2980b9; 
            margin: 0;
        }
        .logout {
            background: #e74c3c;
            color: #fff;
            padding: 8px 16px;
            border-radius: 6px;
            text-decoration: none;
        }
        .logout:hover {
            background: #c0392b;
        }
        .user-info {
            background: #edf2f7;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .user-info p {
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h2>Welcome to Dashboard</h2>
            <a href="index.php?logout=1" class="logout">Logout</a>
        </div>

        <div class="user-info">
            <h3>Your Profile</h3>
            <p><strong>Username:</strong> <?php echo htmlspecialchars($user['username']); ?></p>
            <p><strong>Email:</strong> <?php echo htmlspecialchars($user['email']); ?></p>
        </div>

        <!-- Add more dashboard content here -->
    </div>
</body>
</html>
