<?php
session_start();
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'manager') {
  header("Location: login.php");
  exit;
}

include 'config.php';

$name = $_SESSION['name'];

$sql = "SELECT status, COUNT(*) AS count FROM leave_requests GROUP BY status";
$result = $conn->query($sql);

$statusCounts = [
  'approved' => 0,
  'rejected' => 0,
  'pending' => 0,
];

while ($row = $result->fetch_assoc()) {
  $statusCounts[strtolower($row['status'])] = (int)$row['count'];
}

ob_start();
include 'templates/report.html';
$html = ob_get_clean();

$html = str_replace('<!-- MANAGER NAME -->', htmlspecialchars($name), $html);
$html = str_replace('<!-- APPROVED COUNT -->', $statusCounts['approved'], $html);
$html = str_replace('<!-- REJECTED COUNT -->', $statusCounts['rejected'], $html);
$html = str_replace('<!-- PENDING COUNT -->', $statusCounts['pending'], $html);

echo $html;
