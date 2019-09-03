defmodule Samly.AuthHandler do
  @moduledoc false

  require Logger
  import Plug.Conn
  alias Samly.{Assertion, IdpData, Helper, State, Subject}

  import Samly.RouterUtil, only: [ensure_sp_uris_set: 2, send_saml_request: 5, send_saml_request: 6, redirect: 3]

  @sso_init_resp_template """
  <!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\"
    \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">
  <html xmlns=\"http://www.w3.org/1999/xhtml\" xml:lang=\"en\" lang=\"en\">
    <head>
      <meta http-equiv=\"Content-Type\" content=\"text/html; charset=UTF-8\"/>
    </head>
    <body>
      <script nonce=\"<%= nonce %>\">
        document.addEventListener(\"DOMContentLoaded\", function () {
          document.getElementById(\"sso-req-form\").submit();
        });
      </script>
      <noscript>
        <p><strong>Note:</strong>
          Since your browser does not support JavaScript, you must press
          the button below to proceed.
        </p>
      </noscript>
      <form id=\"sso-req-form\" method=\"post\" action=\"<%= action %>\">
        <%= if target_url do %>
        <input type=\"hidden\" name=\"target_url\" value=\"<%= target_url %>\" />
        <% end %>
        <input type=\"hidden\" name=\"_csrf_token\" value=\"<%= csrf_token %>\" />
        <noscript><input type=\"submit\" value=\"Submit\" /></noscript>
      </form>
    </body>
  </html>
  """

  def initiate_sso_req(conn) do
    import Plug.CSRFProtection, only: [get_csrf_token: 0]

    target_url = conn.private[:samly_target_url] || "/"

    opts = [
      nonce: conn.private[:samly_nonce],
      action: URI.encode(conn.request_path),
      target_url: URI.encode_www_form(target_url),
      csrf_token: get_csrf_token()
    ]

    conn
    |> put_resp_header("content-type", "text/html")
    |> send_resp(200, EEx.eval_string(@sso_init_resp_template, opts))
  end

  def send_signin_req(%{host: host} = conn) do
    %IdpData{id: idp_id, sso_post_url: sso_post, sso_redirect_url: sso_redirect} = idp = conn.private[:samly_idp]
    %IdpData{esaml_idp_rec: idp_rec, esaml_sp_rec: sp_rec} = idp
    sp = ensure_sp_uris_set(sp_rec, conn)

    target_url = conn.private[:samly_target_url] || "/"
    assertion_key = get_session(conn, "samly_assertion_key")

    case State.get_assertion(conn, assertion_key) do
      %Assertion{idp_id: ^idp_id} ->
        conn |> redirect(302, target_url)

      _ ->
        relay_state = State.gen_id()

        {idp_signin_url, req_xml_frag} =
          Helper.gen_idp_signin_req(sp, idp_rec, Map.get(idp, :nameid_format))

        conn
        |> configure_session(renew: true)
        |> put_session("relay_state", relay_state)
        |> put_session("idp_id", idp_id)
        |> put_resp_cookie("target_url", target_url, domain: strip_subdomains(host, 1))
        |> send_saml_request(
          idp_signin_url,
          idp.use_redirect_for_req,
          req_xml_frag,
          relay_state,
          sp: sp, sso_post: sso_post, sso_redirect: sso_redirect
        )
    end

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end

  
  def send_signout_req(conn) do
    %IdpData{id: idp_id, slo_post_url: slo_post, slo_redirect_url: slo_redirect} = idp = conn.private[:samly_idp]
    %IdpData{esaml_idp_rec: idp_rec, esaml_sp_rec: sp_rec} = idp
    sp = ensure_sp_uris_set(sp_rec, conn)

    target_url = conn.private[:samly_target_url] || "/"
    assertion_key = get_session(conn, "samly_assertion_key")

    case State.get_assertion(conn, assertion_key) do
      %Assertion{idp_id: ^idp_id, authn: authn, subject: subject} ->
        session_index = Map.get(authn, "session_index", "")
        subject_rec = Subject.to_rec(subject)

        {:ok, {idp_signout_url, req_xml_frag}} =
          Helper.gen_idp_signout_req(sp, idp_rec, subject_rec, session_index,
            slo_post: slo_post, slo_redirect: slo_redirect, use_redirect?: idp.use_redirect_for_logout_req)

        conn = State.delete_assertion(conn, assertion_key)
        relay_state = State.gen_id()

        conn
        |> put_session("target_url", target_url)
        |> put_session("relay_state", relay_state)
        |> put_session("idp_id", idp_id)
        |> delete_session("samly_assertion_key")
        |> send_saml_request(
          idp_signout_url,
          idp.use_redirect_for_logout_req,
          req_xml_frag,
          relay_state,
          sp: sp, slo_post: slo_post, slo_redirect: slo_redirect
        )

      _ ->
        conn |> send_resp(403, "access_denied")
    end

    # rescue
    #   error ->
    #     Logger.error("#{inspect error}")
    #     conn |> send_resp(500, "request_failed")
  end
  
  defp strip_subdomains(host, n_of_subdomains) do
    host
    |> String.split(".", parts: n_of_subdomains + 1)
    |> List.last
  end
end
