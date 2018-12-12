// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "services/identity/public/cpp/accounts_mutator.h"

#include "components/signin/core/browser/account_info.h"
#include "components/signin/core/browser/account_tracker_service.h"
#include "components/signin/core/browser/profile_oauth2_token_service.h"

namespace identity {

AccountsMutator::AccountsMutator(ProfileOAuth2TokenService* token_service,
                                 AccountTrackerService* account_tracker_service)
    : token_service_(token_service),
      account_tracker_service_(account_tracker_service) {}

AccountsMutator::~AccountsMutator() {}

void AccountsMutator::LoadAccountsFromDisk(
    const std::string& primary_account_id) {
  token_service_->LoadCredentials(primary_account_id);
}

std::string AccountsMutator::AddOrUpdateAccount(
    const std::string& gaia_id,
    const std::string& email,
    const std::string& refresh_token,
    const SetRefreshTokenExtraInfo& extra_info) {
  std::string account_id =
      account_tracker_service_->SeedAccountInfo(gaia_id, email);

  // Add extra info about the account before refreshing the token.
  account_tracker_service_->SetIsChildAccount(account_id,
                                              extra_info.is_child_account);

  // TODO: Handle the remaining extra fields provided along with |extra_info|
  // i.e. |full_name| and |hosted_domain|.

  UpdateRefreshToken(account_id, refresh_token);
  return account_id;
}

// Updates the refresh token of |account_id|, which must be a known account.
void AccountsMutator::UpdateRefreshToken(const std::string& account_id,
                                         const std::string& refresh_token) {
  token_service_->UpdateCredentials(account_id, refresh_token);
}

// Removes the account given by |account_id|. Also revokes the token
// server-side if needed.
void AccountsMutator::RemoveAccount(const std::string& account_id) {
  token_service_->RevokeCredentials(account_id);
}

// Removes all accounts.
void AccountsMutator::RemoveAllAccounts() {
  token_service_->RevokeAllCredentials();
}

}  // namespace identity
