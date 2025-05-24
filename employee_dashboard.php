<?php
session_start();
if (!isset($_SESSION['user_id']) || $_SESSION['role'] !== 'employee') {
  header("Location: login.php");
  exit;
}

include 'config.php';

$user_id = $_SESSION['user_id'];
$name = $_SESSION['name'];

// Fetch leave requests by this user
$stmt = $conn->prepare("SELECT start_date, end_date, reason, status, created_at FROM leave_requests WHERE user_id = ? ORDER BY created_at DESC");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();

$rows_html = '';
while ($row = $result->fetch_assoc()) {
  $status_class = 'status-' . strtolower($row['status']);
  $rows_html .= "<tr>
    <td>{$row['start_date']}</td>
    <td>{$row['end_date']}</td>
    <td>" . htmlspecialchars($row['reason']) . "</td>
    <td class=\"$status_class\">" . ucfirst($row['status']) . "</td>
    <td>{$row['created_at']}</td>
  </tr>";
}

// Load template
ob_start();
include 'templates/employee_dashboard.html';
$html = ob_get_clean();

$html = str_replace('<!-- USER NAME -->', htmlspecialchars($name), $html);
$html = str_replace('<!-- LEAVE REQUEST ROWS -->', $rows_html, $html);

echo $html;
?>
