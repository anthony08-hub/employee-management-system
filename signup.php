<?php
include 'config.php';

$error = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
  $name = trim($_POST['name']);
  $email = trim($_POST['email']);
  $password = password_hash(trim($_POST['password']), PASSWORD_DEFAULT);
  $role = 'employee'; // only employees can register

  if ($name && $email && $password) {
    // Check if email already exists
    $stmt = $conn->prepare("SELECT id FROM users WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();
    if ($stmt->num_rows > 0) {
      $error = "Email is already registered.";
    } else {
      // Insert user
      $stmt = $conn->prepare("INSERT INTO users (name, email, password, role) VALUES (?, ?, ?, ?)");
      $stmt->bind_param("ssss", $name, $email, $password, $role); // Note: Hashing recommended in production
      if ($stmt->execute()) {
        header("Location: login.php");
        exit;
      } else {
        $error = "Failed to register. Please try again.";
      }
    }
  } else {
    $error = "All fields are required.";
  }
}

// Load signup template
ob_start();
include 'templates/signup.html';
$html = ob_get_clean();

if ($error) {
  $html = str_replace(
    '<div id="error-message" style="color:red; font-size:0.9em; margin-top:5px;"></div>',
    "<div id='error-message' style='color:red; font-size:0.9em; margin-top:5px;'>$error</div>",
    $html
  );
}

echo $html;
?>
