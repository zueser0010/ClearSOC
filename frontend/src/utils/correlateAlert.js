export function correlateAlert(alert, allLogs = []) {

  const findings = [];

  const sourceIp =
    alert.sourceIp ||
    alert.src_ip ||
    "N/A";

  const user =
    alert.user ||
    "N/A";

  const host =
    alert.host ||
    "N/A";

  const process =
    alert.process ||
    "N/A";

  const time =
    alert.time ||
    alert.timestamp;

  const alertTime = new Date(time).getTime();

  function addFinding(type, status, evidence) {
    findings.push({
      type,
      status,
      evidence
    });
  }

  // =========================
  // SAME SOURCE IP
  // =========================

  if (sourceIp && sourceIp !== "N/A") {

    const relatedIpLogs = allLogs.filter((log) => {

      const logIp =
        log.sourceIp ||
        log.src_ip ||
        log?.data?.srcip;

      return logIp === sourceIp;
    });

    if (relatedIpLogs.length > 1) {

      addFinding(
        "Source IP Correlation",
        "FOUND",
        `${relatedIpLogs.length} logs found from same source IP ${sourceIp}`
      );

    } else {

      addFinding(
        "Source IP Correlation",
        "NOT FOUND",
        `No additional activity found from source IP ${sourceIp}`
      );
    }

  } else {

    addFinding(
      "Source IP Correlation",
      "NOT CHECKED",
      "Source IP missing from alert"
    );
  }

  // =========================
  // FAILED LOGIN CHECK
  // =========================

  const failedLogins = allLogs.filter((log) => {

    const text = JSON.stringify(log).toLowerCase();

    return (
      text.includes("4625") ||
      text.includes("failed login")
    );
  });

  if (failedLogins.length > 0) {

    addFinding(
      "Failed Login Activity",
      "FOUND",
      `${failedLogins.length} failed login event(s) detected in correlated logs`
    );

  } else {

    addFinding(
      "Failed Login Activity",
      "NOT FOUND",
      "No failed login activity detected"
    );
  }

  // =========================
  // PRIVILEGE EVENTS
  // =========================

  const privilegeEvents = allLogs.filter((log) => {

    const text = JSON.stringify(log).toLowerCase();

    return (
      text.includes("4672") ||
      text.includes("special privileges")
    );
  });

  if (privilegeEvents.length > 0) {

    addFinding(
      "Privilege Escalation Indicators",
      "FOUND",
      `${privilegeEvents.length} privilege-related event(s) observed`
    );

  } else {

    addFinding(
      "Privilege Escalation Indicators",
      "NOT FOUND",
      "No privilege escalation indicators detected"
    );
  }

  // =========================
  // USER CREATION
  // =========================

  const newUsers = allLogs.filter((log) => {

    const text = JSON.stringify(log).toLowerCase();

    return (
      text.includes("4720") ||
      text.includes("user account was created")
    );
  });

  if (newUsers.length > 0) {

    addFinding(
      "Persistence / User Creation",
      "FOUND",
      `${newUsers.length} user account creation event(s) observed`
    );

  } else {

    addFinding(
      "Persistence / User Creation",
      "NOT FOUND",
      "No suspicious user creation activity detected"
    );
  }

  // =========================
  // ADMIN GROUP CHANGES
  // =========================

  const adminChanges = allLogs.filter((log) => {

    const text = JSON.stringify(log).toLowerCase();

    return (
      text.includes("4732") ||
      text.includes("administrators")
    );
  });

  if (adminChanges.length > 0) {

    addFinding(
      "Admin Group Modification",
      "FOUND",
      `${adminChanges.length} admin group modification event(s) detected`
    );

  } else {

    addFinding(
      "Admin Group Modification",
      "NOT FOUND",
      "No admin group modification activity detected"
    );
  }

  // =========================
  // POWERSHELL
  // =========================

  const psEvents = allLogs.filter((log) => {

    const text = JSON.stringify(log).toLowerCase();

    return text.includes("powershell");
  });

  if (psEvents.length > 0) {

    addFinding(
      "PowerShell Activity",
      "FOUND",
      `${psEvents.length} PowerShell-related event(s) observed`
    );

  } else {

    addFinding(
      "PowerShell Activity",
      "NOT FOUND",
      "No PowerShell activity detected"
    );
  }

  // =========================
  // NETWORK ACTIVITY
  // =========================

  const networkEvents = allLogs.filter((log) => {

    const text = JSON.stringify(log).toLowerCase();

    return (
      text.includes('"eventid":"3"') ||
      text.includes("destinationip") ||
      text.includes("network connection")
    );
  });

  if (networkEvents.length > 0) {

    addFinding(
      "Network Activity",
      "FOUND",
      `${networkEvents.length} suspicious outbound/network event(s) observed`
    );

  } else {

    addFinding(
      "Network Activity",
      "NOT FOUND",
      "No suspicious outbound activity detected"
    );
  }

  // =========================
  // TIMELINE WINDOW
  // =========================

  const nearbyEvents = allLogs.filter((log) => {

    const logTime = new Date(
      log.time ||
      log.timestamp
    ).getTime();

    if (!logTime || !alertTime) return false;

    const diff = Math.abs(logTime - alertTime);

    return diff <= 5 * 60 * 1000;
  });

  addFinding(
    "Timeline Correlation",
    "FOUND",
    `${nearbyEvents.length} event(s) detected within ±5 minutes of selected alert`
  );

  return findings;
}
