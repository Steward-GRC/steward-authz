# Obligations service authorization (CampaignService, AckService,
# NotifPrefService, ReportingService).
package steward.obligations

import data.steward.common

default allow := false

# ---- CampaignService ---------------------------------------------------

# Only compliance admins create and close campaigns.
allow if {
	input.method == "steward.obligations.v1.CampaignService/CreateCampaign"
	common.is_compliance_admin(input.claims)
}

allow if {
	input.method == "steward.obligations.v1.CampaignService/CloseCampaign"
	common.is_compliance_admin(input.claims)
}

# ---- AckService --------------------------------------------------------

# A user records their own ack.
allow if {
	input.method == "steward.obligations.v1.AckService/RecordAck"
	common.has_user_id(input.claims)
	input.claims.user_id == input.request.user_id
}

# A user reads their own ack status; compliance-admins can read anyone's.
allow if {
	input.method == "steward.obligations.v1.AckService/GetAckStatus"
	common.has_user_id(input.claims)
	input.claims.user_id == input.request.user_id
}

allow if {
	input.method == "steward.obligations.v1.AckService/GetAckStatus"
	common.is_compliance_admin(input.claims)
}

# ---- NotifPrefService --------------------------------------------------

# Users edit their own prefs.
allow if {
	input.method == "steward.obligations.v1.NotifPrefService/UpsertNotifPref"
	common.has_user_id(input.claims)
	input.claims.user_id == input.request.pref.user_id
}

allow if {
	input.method == "steward.obligations.v1.NotifPrefService/GetNotifPref"
	common.has_user_id(input.claims)
	input.claims.user_id == input.request.user_id
}

# ---- ReportingService --------------------------------------------------

# Completion reports + exports: compliance admins only.
allow if {
	input.method == "steward.obligations.v1.ReportingService/GetCompletionReport"
	common.is_compliance_admin(input.claims)
}

allow if {
	input.method == "steward.obligations.v1.ReportingService/ExportAcks"
	common.is_compliance_admin(input.claims)
}
