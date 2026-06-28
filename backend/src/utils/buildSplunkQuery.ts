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
| eval device_ip_header = 'line.input.attributes.request.http.headers.x-device-ip'
| eval snort_src_ip = coalesce(src_addr, replace(src_ap, ":[0-9]+$", ""), src_ip, src)
| eval src_ip = if(is_snort=1, snort_src_ip, coalesce(device_ip_header, src_ip, src))
| eval user_id = coalesce(username_opa, user, "${username}")

| stats 
    sum(eval(if(is_opa=1 AND user_id="${username}", is_deny, 0))) AS total_denies
    count(eval(is_opa=1 AND user_id="${username}")) AS total_opa_requests
    sum(eval(if(is_snort=1 AND src_ip="${requestIp}", 1, 0))) AS total_snort_alerts
| eval user_id="${username}"

| eval deny_ratio = if(total_opa_requests > 0, total_denies / total_opa_requests, 0)
| fields user_id total_denies total_opa_requests total_snort_alerts deny_ratio

| apply app_risk_model
| rename "predicted(is_attacker)" as P_app
| eval P_app = coalesce(P_app, 1 - exp(-0.4 * total_denies))

| eval P_net = if(total_snort_alerts > 0, 0.95, 0.0)
| eval prob_attack = max(0.1, P_app, P_net)

| eval current_resource = "${payload.request.resource}"
| eval current_action = "${payload.request.action}"
| eval current_role = "${payload.role || "employee"}"

| eval base_impact = 0.5

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
