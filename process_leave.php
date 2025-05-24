<?php
session_start();
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'manager') {
  header("Location: login.php");
  exit;
}

include 'config.php';

if (isset($_GET['action'], $_GET['id'])) {
  $action = $_GET['action'];
  $id = (int)$_GET['id'];
  if (in_array($action, ['approve', 'reject'])) {
    $status = $action === 'approve' ? 'approved' : 'rejected';
    $stmt = $conn->prepare("UPDATE leave_requests SET status = ? WHERE id = ?");
    $stmt->bind_param("si", $status, $id);
    $stmt->execute();
  }
}

header("Location: manager_dashboard.php");
exit;
