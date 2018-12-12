// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "services/identity/public/cpp/accounts_mutator.h"

#include "base/message_loop/message_loop.h"
#include "components/signin/core/browser/account_fetcher_service.h"
#include "components/signin/core/browser/account_tracker_service.h"
#include "components/signin/core/browser/fake_account_fetcher_service.h"
#include "components/signin/core/browser/fake_profile_oauth2_token_service.h"
#include "components/signin/core/browser/test_signin_client.h"
#include "components/sync_preferences/testing_pref_service_syncable.h"
#include "services/identity/public/cpp/accounts_mutator.h"
#include "testing/gtest/include/gtest/gtest.h"

namespace {

const char kTestGaiaId[] = "gaia-id-test_user@test.com";
const char kTestGaiaId2[] = "gaia-id-test_user-2@test.com";
const char kTestEmail[] = "test_user@test.com";
const char kTestEmail2[] = "test_user@test-2.com";
const char kRefreshToken[] = "refresh_token";
const char kRefreshToken2[] = "refresh_token_2";

// Class that observes updates from ProfileOAuth2TokenService.
class TestTokenServiceObserver : public OAuth2TokenService::Observer {
 public:
  explicit TestTokenServiceObserver(OAuth2TokenService* token_service)
      : token_service_(token_service) {
    token_service_->AddObserver(this);
  }
  ~TestTokenServiceObserver() override { token_service_->RemoveObserver(this); }

  void set_on_refresh_tokens_available_callback(
      base::RepeatingCallback<void(const std::string&)> callback) {
    on_refresh_tokens_available_callback_ = std::move(callback);
  }

  void set_on_refresh_tokens_revoked_callback(
      base::RepeatingCallback<void(const std::string&)> callback) {
    on_refresh_tokens_revoked_callback_ = std::move(callback);
  }

  void set_on_refresh_tokens_loaded_callback(base::OnceClosure callback) {
    on_refresh_tokens_loaded_callback_ = std::move(callback);
  }

 private:
  // OAuth2TokenService::Observer:
  void OnRefreshTokenAvailable(const std::string& account_id) override {
    if (on_refresh_tokens_available_callback_)
      std::move(on_refresh_tokens_available_callback_).Run(account_id);
  }

  void OnRefreshTokenRevoked(const std::string& account_id) override {
    if (on_refresh_tokens_revoked_callback_)
      std::move(on_refresh_tokens_revoked_callback_).Run(account_id);
  }

  void OnRefreshTokensLoaded() override {
    if (on_refresh_tokens_loaded_callback_)
      std::move(on_refresh_tokens_loaded_callback_).Run();
  }

  OAuth2TokenService* token_service_;
  base::RepeatingCallback<void(const std::string&)>
      on_refresh_tokens_available_callback_;
  base::RepeatingCallback<void(const std::string&)>
      on_refresh_tokens_revoked_callback_;
  base::OnceClosure on_refresh_tokens_loaded_callback_;
};

}  // namespace

namespace identity {
class AccountsMutatorTest : public testing::Test {
 public:
  AccountsMutatorTest()
      : signin_client_(&pref_service_),
        token_service_(&pref_service_),
        token_service_observer_(&token_service_),
        accounts_mutator_(&token_service_, &account_tracker_service_) {
    ProfileOAuth2TokenService::RegisterProfilePrefs(pref_service_.registry());

    AccountTrackerService::RegisterPrefs(pref_service_.registry());
    account_tracker_service_.Initialize(&pref_service_, base::FilePath());

    AccountFetcherService::RegisterPrefs(pref_service_.registry());
    account_fetcher_ = std::make_unique<AccountFetcherService>();
    account_fetcher_->Initialize(&signin_client_, &token_service_,
                                 &account_tracker_service_,
                                 std::make_unique<TestImageDecoder>());

    // Need to enable network fetches so that AccountFetcherService will talk
    // to the AccountTrackerService to remove the account when revoking tokens.
    account_fetcher_->EnableNetworkFetchesForTest();
  }

  ~AccountsMutatorTest() override {
    account_fetcher_->Shutdown();
    account_fetcher_.reset();
  }

  FakeProfileOAuth2TokenService* token_service() { return &token_service_; }

  AccountTrackerService* account_tracker_service() {
    return &account_tracker_service_;
  }

  TestTokenServiceObserver* token_service_observer() {
    return &token_service_observer_;
  }

  AccountsMutator* accounts_mutator() { return &accounts_mutator_; }

 private:
  base::MessageLoop message_loop_;
  sync_preferences::TestingPrefServiceSyncable pref_service_;
  TestSigninClient signin_client_;
  FakeProfileOAuth2TokenService token_service_;
  AccountTrackerService account_tracker_service_;
  std::unique_ptr<AccountFetcherService> account_fetcher_;
  TestTokenServiceObserver token_service_observer_;
  AccountsMutator accounts_mutator_;

  DISALLOW_COPY_AND_ASSIGN(AccountsMutatorTest);
};

// Tests that requesting a load of accounts results in the notification
// firing that tokens were loaded.
TEST_F(AccountsMutatorTest, LoadAccountsFromDisk) {
  base::RunLoop run_loop;
  token_service_observer()->set_on_refresh_tokens_loaded_callback(
      run_loop.QuitClosure());

  // Load the accounts and ensure that we see the resulting notification that
  // they were loaded.
  accounts_mutator()->LoadAccountsFromDisk("");
  run_loop.Run();
}

// Test that a new account gets added to the AccountTrackerService when calling
// AddOrUpdateAccount() and that a new refresh token becomes available for the
// passed account_id when adding an account for the first time.
TEST_F(AccountsMutatorTest, AddOrUpdateAccount_AddNewAccount) {
  // Declare |run_loop| static, so that we can call it from inside the callback
  // for OAuth2TokenService::Observer::OnRefreshTokenAvailable()
  base::RunLoop run_loop;
  std::string expected_id = account_tracker_service()->PickAccountIdForAccount(
      kTestGaiaId, kTestEmail);

  token_service_observer()->set_on_refresh_tokens_available_callback(
      base::BindRepeating(
          [](base::RunLoop* loop, const std::string& expected_id,
             const std::string& account_id) {
            EXPECT_EQ(account_id, expected_id);
            loop->Quit();
          },
          base::Unretained(&run_loop), expected_id));

  AccountsMutator::SetRefreshTokenExtraInfo extra_info;
  extra_info.full_name = std::string();
  extra_info.hosted_domain = std::string();
  extra_info.is_child_account = false;

  std::string account_id = accounts_mutator()->AddOrUpdateAccount(
      kTestGaiaId, kTestEmail, kRefreshToken, extra_info);
  EXPECT_EQ(account_id, expected_id);
  run_loop.Run();

  EXPECT_TRUE(token_service()->RefreshTokenIsAvailable(account_id));
  EXPECT_FALSE(token_service()->RefreshTokenHasError(account_id));

  AccountInfo account_info =
      account_tracker_service()->GetAccountInfo(account_id);
  EXPECT_EQ(account_info.account_id, expected_id);
  EXPECT_EQ(account_info.email, kTestEmail);
  EXPECT_EQ(account_tracker_service()->GetAccounts().size(), 1U);
}

// Test that no account gets added to the AccountTrackerService  when calling
// AddOrUpdateAccount() if there's an account already tracked for a given id,
// and that its refresh token gets updated if a different one is passed.
TEST_F(AccountsMutatorTest, AddOrUpdateAccount_UpdateExistingAccount) {
  // First of all add the account to the account tracker service.
  base::RunLoop run_loop;
  token_service_observer()->set_on_refresh_tokens_available_callback(
      base::BindRepeating([](base::RunLoop* loop,
                             const std::string& account_id) { loop->Quit(); },
                          base::Unretained(&run_loop)));

  AccountsMutator::SetRefreshTokenExtraInfo extra_info;
  extra_info.full_name = std::string();
  extra_info.hosted_domain = std::string();
  extra_info.is_child_account = false;

  std::string account_id = accounts_mutator()->AddOrUpdateAccount(
      kTestGaiaId, kTestEmail, kRefreshToken, extra_info);
  run_loop.Run();

  EXPECT_TRUE(token_service()->RefreshTokenIsAvailable(account_id));
  EXPECT_FALSE(token_service()->RefreshTokenHasError(account_id));
  EXPECT_EQ(account_tracker_service()->GetAccounts().size(), 1U);

  // Now try adding the account again with the same account id but with a
  // different refresh token, and check that only the token gets updated.
  base::RunLoop run_loop2;
  std::string expected_id = account_tracker_service()->PickAccountIdForAccount(
      kTestGaiaId, kTestEmail);

  token_service_observer()->set_on_refresh_tokens_available_callback(
      base::BindRepeating(
          [](base::RunLoop* loop, const std::string& expected_id,
             const std::string& account_id) {
            EXPECT_EQ(account_id, expected_id);
            loop->Quit();
          },
          base::Unretained(&run_loop2), expected_id));

  std::string account_id2 = accounts_mutator()->AddOrUpdateAccount(
      kTestGaiaId, kTestEmail, kRefreshToken2, extra_info);
  EXPECT_EQ(account_id2, expected_id);

  run_loop2.Run();

  EXPECT_TRUE(token_service()->RefreshTokenIsAvailable(account_id2));
  EXPECT_FALSE(token_service()->RefreshTokenHasError(account_id2));
  EXPECT_EQ(account_tracker_service()->GetAccounts().size(), 1U);
}

// Test that the refresh token for an existing account gets updated when calling
// UpdateRefreshToken() for the account's Id.
TEST_F(AccountsMutatorTest, UpdateRefreshToken_ExistingAccount) {
  // First of all add the account to the account tracker service.
  base::RunLoop run_loop;
  token_service_observer()->set_on_refresh_tokens_available_callback(
      base::BindRepeating([](base::RunLoop* loop,
                             const std::string& account_id) { loop->Quit(); },
                          base::Unretained(&run_loop)));

  AccountsMutator::SetRefreshTokenExtraInfo extra_info;
  extra_info.full_name = std::string();
  extra_info.hosted_domain = std::string();
  extra_info.is_child_account = false;

  std::string account_id = accounts_mutator()->AddOrUpdateAccount(
      kTestGaiaId, kTestEmail, kRefreshToken, extra_info);
  run_loop.Run();

  EXPECT_TRUE(token_service()->RefreshTokenIsAvailable(account_id));
  EXPECT_FALSE(token_service()->RefreshTokenHasError(account_id));
  EXPECT_EQ(account_tracker_service()->GetAccounts().size(), 1U);

  // Now update the refresh token for that account to something different.
  base::RunLoop run_loop2;
  std::string expected_id = account_tracker_service()->PickAccountIdForAccount(
      kTestGaiaId, kTestEmail);

  token_service_observer()->set_on_refresh_tokens_available_callback(
      base::BindRepeating(
          [](base::RunLoop* loop, const std::string& expected_id,
             const std::string& account_id) {
            EXPECT_EQ(account_id, expected_id);
            loop->Quit();
          },
          base::Unretained(&run_loop2), expected_id));

  accounts_mutator()->UpdateRefreshToken(account_id, kRefreshToken2);
  run_loop2.Run();

  EXPECT_TRUE(token_service()->RefreshTokenIsAvailable(account_id));
  EXPECT_FALSE(token_service()->RefreshTokenHasError(account_id));
  EXPECT_EQ(account_tracker_service()->GetAccounts().size(), 1U);
}

// Test that attempting to "update" the refresh token for non-existing account
// gets the token into the PO2TS, and creates a new account in the ATS.
TEST_F(AccountsMutatorTest, UpdateRefreshToken_NonExistingAccount) {
  // Updating the refresh token for an account not yet seeded in the account
  // tracker service, should result in the token making it through to the PO2TS
  // and the account tracker service registering a new AccountTrackerService
  // registering a new account as instructed by AccountFetcherService.
  base::RunLoop run_loop;
  token_service_observer()->set_on_refresh_tokens_available_callback(
      base::BindRepeating(
          [](base::RunLoop* loop, const std::string& account_id) {
            EXPECT_EQ(account_id, kTestGaiaId);
            loop->Quit();
          },
          base::Unretained(&run_loop)));

  accounts_mutator()->UpdateRefreshToken(kTestGaiaId, kRefreshToken);
  run_loop.Run();

  EXPECT_TRUE(token_service()->RefreshTokenIsAvailable(kTestGaiaId));
  EXPECT_FALSE(token_service()->RefreshTokenHasError(kTestGaiaId));
  EXPECT_EQ(account_tracker_service()->GetAccounts().size(), 1U);
}

// Test that attempting to remove a non-existing account should not result in
// firing any callback from AccountTrackerService or ProfileOAuth2TokenService.
TEST_F(AccountsMutatorTest, RemoveAccount_NonExistingAccount) {
  base::RunLoop run_loop;
  token_service_observer()->set_on_refresh_tokens_available_callback(
      base::BindRepeating([](const std::string& account_id) {
        // This callback should not be invoked now.
        EXPECT_TRUE(false);
      }));

  accounts_mutator()->RemoveAccount(kTestGaiaId);
  run_loop.RunUntilIdle();

  EXPECT_FALSE(token_service()->RefreshTokenIsAvailable(kTestGaiaId));
  EXPECT_FALSE(token_service()->RefreshTokenHasError(kTestGaiaId));
  EXPECT_EQ(account_tracker_service()->GetAccounts().size(), 0U);
}

// Test that attempting to remove an existing account should result in firing
// the right callbacks from AccountTrackerService or ProfileOAuth2TokenService.
TEST_F(AccountsMutatorTest, RemoveAccount_ExistingAccount) {
  // First of all add the account to the account tracker service.
  base::RunLoop run_loop;
  token_service_observer()->set_on_refresh_tokens_available_callback(
      base::BindRepeating([](base::RunLoop* loop,
                             const std::string& account_id) { loop->Quit(); },
                          base::Unretained(&run_loop)));

  AccountsMutator::SetRefreshTokenExtraInfo extra_info;
  extra_info.full_name = std::string();
  extra_info.hosted_domain = std::string();
  extra_info.is_child_account = false;

  std::string account_id = accounts_mutator()->AddOrUpdateAccount(
      kTestGaiaId, kTestEmail, kRefreshToken, extra_info);
  run_loop.Run();

  EXPECT_TRUE(token_service()->RefreshTokenIsAvailable(account_id));
  EXPECT_FALSE(token_service()->RefreshTokenHasError(account_id));
  EXPECT_EQ(account_tracker_service()->GetAccounts().size(), 1U);

  // Now remove the account that we just added.
  base::RunLoop run_loop2;
  std::string expected_id = account_tracker_service()->PickAccountIdForAccount(
      kTestGaiaId, kTestEmail);

  token_service_observer()->set_on_refresh_tokens_revoked_callback(
      base::BindRepeating(
          [](base::RunLoop* loop, const std::string& expected_id,
             const std::string& account_id) {
            EXPECT_EQ(account_id, expected_id);
            loop->Quit();
          },
          base::Unretained(&run_loop2), expected_id));

  accounts_mutator()->RemoveAccount(account_id);
  run_loop2.Run();

  EXPECT_FALSE(token_service()->RefreshTokenIsAvailable(account_id));
  EXPECT_FALSE(token_service()->RefreshTokenHasError(account_id));
  EXPECT_EQ(account_tracker_service()->GetAccounts().size(), 0U);
}

// Test that attempting to remove all accounts removes all the tokens from the
// PO2TS and every account from the AccountTrackerService.
TEST_F(AccountsMutatorTest, RemoveAllAccounts) {
  // First of all the fist account to the account tracker service.
  base::RunLoop run_loop;
  token_service_observer()->set_on_refresh_tokens_available_callback(
      base::BindRepeating([](base::RunLoop* loop,
                             const std::string& account_id) { loop->Quit(); },
                          base::Unretained(&run_loop)));

  AccountsMutator::SetRefreshTokenExtraInfo extra_info;
  extra_info.full_name = std::string();
  extra_info.hosted_domain = std::string();
  extra_info.is_child_account = false;

  std::string account_id = accounts_mutator()->AddOrUpdateAccount(
      kTestGaiaId, kTestEmail, kRefreshToken, extra_info);
  run_loop.Run();

  EXPECT_TRUE(token_service()->RefreshTokenIsAvailable(account_id));
  EXPECT_FALSE(token_service()->RefreshTokenHasError(account_id));
  EXPECT_EQ(account_tracker_service()->GetAccounts().size(), 1U);

  // Now add the second account.
  base::RunLoop run_loop2;
  token_service_observer()->set_on_refresh_tokens_available_callback(
      base::BindRepeating([](base::RunLoop* loop,
                             const std::string& account_id) { loop->Quit(); },
                          base::Unretained(&run_loop2)));

  std::string account_id2 = accounts_mutator()->AddOrUpdateAccount(
      kTestGaiaId2, kTestEmail2, kRefreshToken2, extra_info);
  run_loop2.Run();

  EXPECT_TRUE(token_service()->RefreshTokenIsAvailable(account_id2));
  EXPECT_FALSE(token_service()->RefreshTokenHasError(account_id2));
  EXPECT_EQ(account_tracker_service()->GetAccounts().size(), 2U);

  // Now remove everything and check that there are no lingering accounts, nor
  // refresh tokens associated to |kTestGaiaId| and |kTestGaiaId2| afterwards.
  base::RunLoop run_loop3;
  accounts_mutator()->RemoveAllAccounts();
  run_loop3.RunUntilIdle();

  EXPECT_FALSE(token_service()->RefreshTokenIsAvailable(kTestGaiaId));
  EXPECT_FALSE(token_service()->RefreshTokenIsAvailable(kTestGaiaId2));
  EXPECT_EQ(account_tracker_service()->GetAccounts().size(), 0U);
}

}  // namespace identity
