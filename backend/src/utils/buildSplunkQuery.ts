import { RiskEvaluateRequest } from "../types/risk";

function escapeSplunkValue(value: string): string {
  return value.replace(/"/g, '\\"');
}

export function buildSplunkQuery(
  payload: RiskEvaluateRequest,
  window: string
): string {
  const username = escapeSplunkValue(payload.user);
  const requestIp = escapeSplunkValue(
    payload.network?.ip || payload.device?.ip || ""
  );

  return `
search ((index=zerotrust sourcetype=opa_decision) OR (index=zerotrust sourcetype=_json source="/opt/splunk/var/log/snort/alert_json.txt")) earliest=${window} latest=now
| eval is_opa = if(sourcetype="opa_decision", 1, 0)
| eval is_snort = if(sourcetype="_json" AND source="/opt/splunk/var/log/snort/alert_json.txt", 1, 0)
| spath input=_raw path=line.result.allowed output=allowed
| spath input=_raw path=line.result.user output=username_opa
| eval is_deny = if(is_opa=1 AND allowed="false", 1, 0)
| eval reason_time = if(is_deny=1 AND match('line.result.deny_reasons{}', "outside_working_hours"), 1, 0)
| eval reason_priv = if(is_deny=1 AND match('line.result.deny_reasons{}', "role_not_allowed|action_not_allowed|department_not_allowed"), 1, 0)
| eval reason_auth = if(is_deny=1 AND match('line.result.deny_reasons{}', "untrusted_device|device_not_active|mfa_required|ja3_fingerprint_blocked|ip_not_in_allowed_zone|unsupported_os"), 1, 0)

| eval device_ip_header = 'line.input.attributes.request.http.headers.x-device-ip'
| eval snort_src_ip = coalesce(src_addr, replace(src_ap, ":[0-9]+$", ""), src_ip, src)
| eval src_ip = if(is_snort=1, snort_src_ip, coalesce(device_ip_header, src_ip, src))
| eval user_id = coalesce(username_opa, user, "${username}")

| stats 
    sum(eval(if(is_opa=1 AND user_id="${username}", is_deny, 0))) AS total_denies
    sum(eval(if(is_opa=1 AND user_id="${username}", reason_time, 0))) AS time_denies
    sum(eval(if(is_opa=1 AND user_id="${username}", reason_priv, 0))) AS priv_denies
    sum(eval(if(is_opa=1 AND user_id="${username}", reason_auth, 0))) AS auth_denies
    count(eval(is_opa=1 AND user_id="${username}")) AS total_opa_requests
    dc(eval(if(is_opa=1 AND user_id="${username}", src_ip, null()))) AS distinct_ips
    sum(eval(if(is_snort=1 AND src_ip="${requestIp}", 1, 0))) AS total_snort_alerts
| eval user_id="${username}"

| eval deny_ratio = if(total_opa_requests > 0, total_denies / total_opa_requests, 0)
| fields user_id total_denies time_denies priv_denies auth_denies distinct_ips total_opa_requests total_snort_alerts deny_ratio

| apply app_risk_model
| eval P_app_prob = 'probability(is_attacker=1)'
| rename "predicted(is_attacker)" as P_app_pred
| eval formula_risk = 1 - exp(-0.4 * priv_denies - 0.2 * auth_denies - 0.1 * distinct_ips - 0.05 * time_denies)
| eval P_app = if(isnotnull(P_app_prob), P_app_prob, max(coalesce(P_app_pred, 0), formula_risk))

| eval P_net = if(total_snort_alerts > 0, 0.95, 0.0)
| eval prob_attack = max(0.1, P_app, P_net)

| eval current_resource = "${payload.request.resource}"
| eval current_action = "${payload.request.action}"
| eval current_role = "${payload.role || "employee"}"

| eval base_impact = case(
    current_resource="employee_records" AND current_action="read", 0.5,
    current_resource="employee_records" AND current_action="write", 0.8,
    current_resource="employee_records" AND current_action="delete", 1.0,
    current_resource="financial_data" AND current_action="read", 0.6,
    current_resource="financial_data" AND current_action="write", 1.0,
    current_resource="public_info" AND current_action="read", 0.1,
    current_resource="public_info" AND current_action="write", 0.5,
    current_resource="system_config" AND current_action="read", 0.7,
    current_resource="system_config" AND current_action="write", 1.0,
    true(), 0.5
  )

| eval role_mod = case(current_role="admin", 0.2, current_role="hr", 0.1, true(), 0.0)
| eval impact = min(1.0, base_impact + role_mod)

| eval risk_score = prob_attack * impact

| eval severity=case(
    risk_score<0.3,"safe",
    risk_score<0.6,"warning",
    risk_score<0.8,"danger",
    true(),"critical"
  )

| table user_id risk_score prob_attack impact severity total_denies total_snort_alerts
  `.trim();
}
