class Fray < Formula
  include Language::Python::Virtualenv

  desc "AI-Powered WAF Security Testing Platform — 4,000+ attack payloads, 25 WAF fingerprints"
  homepage "https://github.com/dalisecurity/fray"
  url "https://files.pythonhosted.org/packages/fb/69/28d252529163597a3e16cb1e65b40b756042f8ddefb43a152fd4c2338fee/fray-3.4.0.tar.gz"
  sha256 "1801a53c60b8318e5ef9f1f398e4fa1b993c4e66cc075b960f28c5487b75b538"
  license "MIT"

  depends_on "python@3.12"

  resource "rich" do
    url "https://files.pythonhosted.org/packages/ab/3a/0316b28d0761c6734d6bc14e770d85506c986c85ffb239e688eeaab2c2bc/rich-13.9.4.tar.gz"
    sha256 "439594978a49a09530cff7ebc4b5c7103ef57baf48d5ea3184f21d9a2befa098"
  end

  resource "markdown-it-py" do
    url "https://files.pythonhosted.org/packages/38/71/3b932df36c1a044d397a1f92d1cf91ee0a503d91e470cbd670aa66b07ed0/markdown-it-py-3.0.0.tar.gz"
    sha256 "e3f60a94fa066dc52ec76661e37c851cb232d92f9886b15cb560aaada2df8feb"
  end

  resource "mdurl" do
    url "https://files.pythonhosted.org/packages/d6/54/cfe61301667036ec958cb99bd3efefba235e65cdeb9c84d24a8293ba1d90/mdurl-0.1.2.tar.gz"
    sha256 "bb413d29f5eea38f31dd4754dd7377d4465116fb207585f97bf925588687c1ba"
  end

  resource "pygments" do
    url "https://files.pythonhosted.org/packages/7c/2d/c3338d48ea6cc0feb8446d8e6937e1408088a72a39937982cc6111d17f84/pygments-2.19.1.tar.gz"
    sha256 "61c16d2a8576dc0649d9f39e089b5f02bcd27fba10d8fb4dcc28173f7a45151f"
  end

  def install
    virtualenv_install_with_resources
  end

  test do
    assert_match "Fray", shell_output("#{bin}/fray --version 2>&1", 0)

    # Verify help text
    assert_match "WAF", shell_output("#{bin}/fray --help 2>&1", 0)
  end
end
