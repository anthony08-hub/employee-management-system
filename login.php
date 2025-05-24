<?php
include 'config.php';

$error = '';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
  $email = $_POST['email'] ?? '';
  $password = $_POST['password'] ?? '';

  $stmt = $conn->prepare("SELECT id, name, role, password FROM users WHERE email = ?");
  $stmt->bind_param("s", $email);
  $stmt->execute();
  $result = $stmt->get_result();

  if ($result->num_rows == 1) {
    $user = $result->fetch_assoc();
    // For demo, passwords stored as plain text; in prod use password_hash + password_verify
    if (password_verify($password, $user['password'])) {
      session_start();
      $_SESSION['user_id'] = $user['id'];
      $_SESSION['name'] = $user['name'];
      $_SESSION['role'] = $user['role'];
      if ($user['role'] === 'manager') {
        header("Location: manager_dashboard.php");
      } else {
        header("Location: employee_dashboard.php");
      }
      exit;
    } else {
      $error = "Invalid password";
    }
  } else {
    $error = "Invalid email";
  }
}

// Load login template and inject error message if any
ob_start();
include 'templates/login.html';
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
