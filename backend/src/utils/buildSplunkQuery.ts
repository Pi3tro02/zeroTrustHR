import { RiskEvaluateRequest } from "../types/risk";

function escapeSplunkValue(value: string): string {
  return value.replace(/"/g, '\\"');
}

export function buildSplunkQuery(
  payload: RiskEvaluateRequest,
  window: string
): string {
  const username = escapeSplunkValue(payload.user);

  return `
search index=zerotrust sourcetype=opa_decision earliest=${window} latest=now
| spath path=line.msg output=msg
| spath path=line.path output=decision_path
| search msg="Decision Log" decision_path="authz/response"
| spath path=line.result.user output=username
| spath path=line.result.resource output=resource_name
| spath path=line.result.allowed output=allowed
| spath path=line.input.attributes.request.http.headers.x-device-ip output=device_ip
| spath path=line.input.attributes.request.http.headers.x-ja3 output=ja3
| spath path=line.input.attributes.request.http.headers.x-device-trusted output=device_trusted
| eval resource_name=replace(resource_name, "-", "_")
| lookup asset_weights.csv resource_name OUTPUT risk_multiplier benefit_score sensitivity
| eval risk_multiplier=coalesce(risk_multiplier,1.0)
| eval benefit_score=coalesce(benefit_score,1.0)
| eval allowed_str=tostring(allowed)
| eval trusted_str=lower(tostring(device_trusted))
| eval is_deny=if(allowed_str="false",1,0)
| eval is_allow=if(allowed_str="true",1,0)
| eval trusted_penalty=if(trusted_str="false",0.5,0)
| eval event_risk_penalty=(is_deny*risk_multiplier)+trusted_penalty
| eval benefit_gained=is_allow*benefit_score
| stats
    sum(event_risk_penalty) AS total_risk
    sum(benefit_gained) AS total_benefit
    count(eval(is_deny=1)) AS recent_denies
    count(eval(is_allow=1)) AS recent_allows
    dc(device_ip) AS distinct_device_ips
    dc(ja3) AS distinct_ja3
    dc(trusted_str) AS distinct_trust_states
    values(resource_name) AS resources_touched
    values(sensitivity) AS sensitivities
    BY username
| search username="${username}"
| eval anomaly_penalty=if(distinct_trust_states>1,1.0,0)
| eval total_risk=total_risk+anomaly_penalty
| eval profit=total_benefit-total_risk
| eval risk_cover=if(profit>=0,"OK","VIOLATED")
| eval severity=case(
    profit>=10,"safe",
    profit>=0,"warning",
    profit>=-10,"danger",
    true(),"critical"
  )
| eval risk_score=case(
    profit>=10,0.2,
    profit>=0,0.5,
    profit>-5,0.7,
    profit>=-10,0.8,
    true(),0.95
  )
| table username risk_score severity profit risk_cover recent_denies recent_allows distinct_device_ips distinct_ja3 distinct_trust_states
`.trim();
}