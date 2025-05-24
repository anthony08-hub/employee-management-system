<?php
session_start();
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'employee') {
  header("Location: login.php");
  exit;
}

include 'config.php';

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
  $user_id = $_SESSION['user_id'];
  $start_date = $_POST['start_date'] ?? '';
  $end_date = $_POST['end_date'] ?? '';
  $reason = $_POST['reason'] ?? '';

  if ($start_date && $end_date && $reason) {
    $stmt = $conn->prepare("INSERT INTO leave_requests (user_id, start_date, end_date, reason, status, created_at) VALUES (?, ?, ?, ?, 'pending', NOW())");
    $stmt->bind_param("isss", $user_id, $start_date, $end_date, $reason);
    $stmt->execute();
  }
}

header("Location: employee_dashboard.php");
exit;
