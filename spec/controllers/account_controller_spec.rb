require 'spec_helper'

describe AccountController do
  # TODO: can't do this yet, as successful_authentication is stubbed:
  # integrate_views
  before :each do
    @request.env['HTTPS'] = 'on'
  end

  describe "#login" do
    context "on an http request" do
      it "redirects to https" do
        @request.env['HTTPS'] = nil
        get(:login)
        url = "https://#{@request.host}#{@request.request_uri}"
        response.should redirect_to url
      end
    end

    context "given an invitation token in the session" do
      context "with invitation token passed as a param" do
        it "assigns the params version to @invitation_token" do
          session[:invitation_token] = 'stuff'
          get(:login, :invitation_token => 'blah')
          assigns(:invitation_token).should == 'blah'
        end
      end

      context "without invitiation token passed as param" do
        it "assigns the session version to @invitation_token" do
          session[:invitation_token] = 'stuff'
          get(:login)
          assigns(:invitation_token).should == 'stuff'
        end
      end
    end

    context "when request is a GET" do
      before :each do
        Setting.stub(:openid?).and_return(true)
        controller.stub(:using_open_id?).and_return(true)
      end

      it "logs out the user" do
        user = Factory.create(:user)
        User.current = user
        get(:login)
        User.current.should == User.anonymous
      end

      it "sets the session invitation_token" do
        get(:login, :invitation_token => 'blah')
        session[:invitation_token].should == 'blah'
      end

      it "renders the static layout" do
        get(:login)
        response.layout.should == 'layouts/static'
      end
    end

    context "when request is not a GET" do
      context "when openid" do
        it "authenticates via openid" do
          Setting.should_receive(:openid?).and_return(true)
          controller.should_receive(:using_open_id?).and_return(true)
          controller.should_receive(:open_id_authenticate).with('blah')
          post(:login, :openid_url => 'blah')
        end
      end

      context "when not openid" do
        it "authenticates via password" do
          controller.should_receive(:password_authentication).with('blah')
          post(:login, :invitation_token => 'blah')
        end
      end
    end
  end

  describe '#rpx_token' do
    before :each do
      controller.stub(:reactivate_user)
      controller.stub(:successful_authentication)
      controller.stub(:create_new_user)
      controller.stub(:find_user_by_identifier).and_return(true)
    end

    it "tries to find the user by identifier" do
      controller.should_receive(:find_user_by_identifier).and_return(true)
      get(:rpx_token)
    end

    context "when the user is not found by identifier" do
      before :each do
        controller.stub(:find_user_by_identifier).and_return(false)
      end

      it "tries to find the user by mail" do
        controller.should_receive(:find_user_by_mail)
        get(:rpx_token)
      end

      context "when the user is not found by mail" do
        it "creates a new user" do
          controller.stub(:find_user_by_mail).and_return(false)
          controller.should_receive(:create_new_user)
          get(:rpx_token)
        end
      end
    end

    it "reactivates the user" do
      controller.should_receive(:reactivate_user)
      get(:rpx_token)
    end

    it "runs the successful_authentication flow" do
      controller.stub(:reactivate_user).and_return('my message')
      controller.should_receive(:successful_authentication).with(nil, nil, 'my message')
      get(:rpx_token)
    end
  end

  describe '#logout' do
    let(:user) { Factory.create(:user) }

    before :each do
      User.current = user
      @token = Token.create(:user => user, :action => 'autologin')
      request.cookies["autologin"] = @token.value
      get(:logout)
    end

    it 'deletes the autologin cookie' do
      # for some reason both request.cookies and response.cookies are nil regardless
      controller.send(:cookies)[:autologin].should_not be
    end

    it 'deletes all autologin tokens for the given user' do
      Token.find_by_id(@token.id).should_not be
    end

    it 'sets the currently logged in user to nil' do
      User.current.should be_anonymous
    end

    it 'redirects to the homepage' do
      response.should redirect_to home_url
    end
  end

  describe '#lost_password' do
    before :each do
      Setting.stub(:lost_password?).and_return(true)
      controller.stub(:validate_token)
      controller.stub(:create_token)
    end

    context "when lost_password setting is not set" do
      it "redirects to home_url" do
        Setting.stub(:lost_password?).and_return(false)
        get(:lost_password)
        response.should redirect_to(home_url)
      end
    end

    it "validates the token" do
      controller.should_receive(:validate_token)
      get(:lost_password)
    end

    context "when the token does not validate" do
      it "creates a token" do
        controller.stub(:validate_token)
        controller.should_receive(:create_token)
        get(:lost_password)
      end
    end
  end

  describe '#register' do
    before :each do
      controller.stub(:check_registration).and_return(true)
    end

    context "when check_registration fails" do
      it "redirects to home_url" do
        controller.stub(:check_registration).and_return(false)
        get(:register)
        response.should redirect_to(home_url)
      end
    end

    it "picks a plan" do
      controller.should_receive(:pick_plan)
      get(:register)
    end

    context "when the request is a GET" do
      it "logs out the user and invites them to login" do
        controller.should_receive(:logout_and_invite)
        get(:register)
      end

      it "renders the static layout" do
        get(:register)
        response.layout.should == 'layouts/static'
      end
    end

    context "when the request is not a GET" do
      before :each do
        controller.stub(:register_user)
      end

      it "initializes the user with their chosen plan" do
        controller.should_receive(:initialize_user_with_plan)
        post(:register)
      end

      context "when the user is registered from an auth source" do
        it "does not render the static layout" do
          controller.stub(:register_user_with_auth_source).and_return(true)
          post(:register)
          response.layout.should_not == 'layouts/static'
        end
      end

      context "when the user is not registered from an auth source" do
        before :each do
          controller.stub(:register_user_with_auth_source)
        end

        context "when the user registered elsewise" do
          it "does not render the static layout" do
            controller.stub(:register_user).and_return(true)
            post(:register)
            response.layout.should_not == 'layouts/static'
          end
        end

        context "when the user does not register" do
          it "renders the static layout" do
            post(:register)
            response.layout.should == 'layouts/static'
          end
        end
      end
    end
  end

  describe '#activate' do
    context "if self_registration is not set" do
      it "redirects to home_url" do
        user = Factory.create(:user, :status => User::STATUS_REGISTERED)
        token = Token.create(:user => user, :action => 'register')
        Setting.stub(:self_registration?).and_return(false)
        get(:activate, :token => token.value)
        response.should redirect_to(home_url)
      end
    end

    context "if params[:token] is not present" do
      it "redirects to home_url" do
        user = Factory.create(:user, :status => User::STATUS_REGISTERED)
        token = Token.create(:user => user, :action => 'register')
        Setting.stub(:self_registration?).and_return(true)
        get(:activate)
        response.should redirect_to(home_url)
      end
    end

    context "if the token is not found" do
      it "redirects to home_url" do
        Setting.stub(:self_registration?).and_return(true)
        get(:activate, :token => 'blah')
        response.should redirect_to(home_url)
      end
    end

    context "if the token is found but expired" do
      it "redirects to home_url" do
        Setting.stub(:self_registration?).and_return(true)
        user = Factory.create(:user, :status => User::STATUS_REGISTERED)
        token = Token.create(:user => user, :action => 'register')
        token.stub(:expired?).and_return(true)
        Token.should_receive(:find_by_action_and_value).
          with('register', token.value).
          and_return(token)
        get(:activate, :token => token.value)
        response.should redirect_to(home_url)
      end
    end

    context "if the user is not registered" do
      it "redirects to home_url" do
        Setting.stub(:self_registration?).and_return(true)
        user = Factory.create(:user, :status => User::STATUS_ACTIVE)
        token = Token.create(:user => user, :action => 'register')
        get(:activate, :token => token.value)
        response.should redirect_to(home_url)
      end
    end

    context "if the user is valid" do
      let(:user) { Factory.create(:user, :status => User::STATUS_REGISTERED) }
      let(:token) { Token.create(:user => user, :action => 'register') }

      before :each do
        Setting.stub(:self_registration?).and_return(true)
        controller.stub(:successful_authentication)
      end

      it "changes the user's status to active" do
        get(:activate, :token => token.value)
        user.reload.status.should == User::STATUS_ACTIVE
      end

      it "destroys the token" do
        get(:activate, :token => token.value)
        Token.find_by_id(token.id).should_not be
      end

      it "flashes a success message" do
        get(:activate, :token => token.value)
        response.session[:flash][:success].should =~ /activated/
      end

      it "authenticates the user" do
        controller.should_receive(:successful_authentication).with(user)
        get(:activate, :token => token.value)
      end
    end

    context "if the user is invalid" do
      let(:user) { Factory.create(:user, :status => User::STATUS_REGISTERED) }
      let(:token) { Token.create(:user => user, :action => 'register') }

      before :each do
        Setting.stub(:self_registration?).and_return(true)
        user.stub(:save).and_return(false)
        token.stub(:user).and_return(user)
        Token.stub(:find_by_action_and_value).and_return(token)
        get(:activate, :token => token.value)
      end

      it "renders the login page" do
        response.should render_template('login')
      end

      it "renders the static layout" do
        response.layout.should == 'layouts/static'
      end
    end
  end

  describe '#cancel' do
    let(:user) { Factory.create(:user, :mail => 'bob@bob.com') }

    before :each do
      User.stub(:current).and_return(user)
    end

    it "cancels the current user's account" do
      get(:cancel)
      user.reload.should be_canceled
    end

    it "renders an account canceled message" do
      controller.should_receive(:render_message).with(/canceled/)
      get(:cancel)
    end
  end

  describe '#password_authentication' do
    let(:user) { Factory.create(:user) }
    before :each do
      controller.stub(:invalid_credentials)
    end

    it "tries to login the user" do
      User.should_receive(:try_to_login).with('bill', 'bill_password')
      controller.stub(:params).and_return({ :username => 'bill', :password => 'bill_password' })
      controller.send(:password_authentication)
    end

    context "when the user does not login properly" do
      it "goes through the invalid credentials flow" do
        User.stub(:try_to_login)
        controller.should_receive(:invalid_credentials)
        controller.send(:password_authentication)
      end
    end

    context "when the user is a new record" do
      it "goes through the onthefly creation failed flow" do
        user.login = 'bill'
        user.auth_source_id = 15
        user.stub(:new_record?).and_return(true)
        User.stub(:try_to_login).and_return(user)
        controller.should_receive(:onthefly_creation_failed).with(user, { :login => 'bill', :auth_source_id => 15 })
        controller.send(:password_authentication)
      end
    end

    context "when the user is not active" do
      it "goes through the inactive_user flow" do
        user.stub(:active?).and_return(false)
        User.stub(:try_to_login).and_return(user)
        controller.should_receive(:inactive_user)
        controller.send(:password_authentication)
      end
    end

    context "otherwise" do
      context "when the user is active" do
        it "goes through the successful_authentication flow" do
          user.stub(:active?).and_return(true)
          User.stub(:try_to_login).and_return(user)
          controller.should_receive(:successful_authentication).with(user, 'token')
          controller.send(:password_authentication, 'token')
        end
      end
    end
  end

end
