# frozen_string_literal: true

RSpec.describe LinkSafety::SiteOrigin do
  before do
    allow(Discourse).to receive(:base_url).and_return("https://forum.example")
    allow(Discourse).to receive(:base_url_no_prefix).and_return("https://forum.example")
    allow(Discourse).to receive(:current_hostname).and_return("forum.example")
    allow(SiteSetting).to receive(:scheme).and_return("https")
  end

  it "trusts only the exact current HTTP origin" do
    expect(described_class.same?("https://forum.example/t/1")).to eq(true)
    expect(described_class.same?("https://forum.example:443/t/1")).to eq(true)
    expect(described_class.same?("https://forum.example:8443/t/1")).to eq(false)
    expect(described_class.same?("http://forum.example/t/1")).to eq(false)
  end

  it "does not implicitly trust an unrelated asset/storage origin" do
    expect(described_class.same?("https://cdn.example/assets/x.js")).to eq(false)
  end
  it "does not add the default port as trusted when Discourse itself runs on a custom port" do
    allow(Discourse).to receive(:base_url).and_return("https://forum.example:8443")
    allow(Discourse).to receive(:base_url_no_prefix).and_return("https://forum.example:8443")

    expect(described_class.same?("https://forum.example:8443/t/1")).to eq(true)
    expect(described_class.same?("https://forum.example/t/1")).to eq(false)
  end

end
