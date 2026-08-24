# frozen_string_literal: true

RSpec.describe LinkSafety::Extractor do
  describe ".post_raw_result" do
    it "extracts a full onebox source from the cooked post" do
      raw = "https://onebox.example/article"
      analyzer = instance_double(PostAnalyzer)
      allow(PostAnalyzer).to receive(:new).with(raw, 42).and_return(analyzer)
      allow(analyzer).to receive(:cook).and_return(
        '<aside class="onebox" data-onebox-src="https://onebox.example/article"><a href="https://onebox.example/article">Preview</a></aside>',
      )

      result = described_class.post_raw_result(raw, 42)

      expect(result.error_code).to be_nil
      expect(result.urls).to eq(["https://onebox.example/article"])
    end

    it "keeps external links while removing Discourse-generated relative links" do
      analyzer = instance_double(PostAnalyzer)
      allow(PostAnalyzer).to receive(:new).and_return(analyzer)
      allow(analyzer).to receive(:cook).and_return(
        <<~HTML,
          <p>
            <a class="mention" href="/u/example">@example</a>
            <a class="mention-group" href="/groups/team">@team</a>
            <a class="hashtag" href="/tag/security">#security</a>
            <a href="/t/topic/123">Internal topic</a>
            <a href="https://external.example/path">External</a>
          </p>
        HTML
      )

      result = described_class.post_raw_result("raw", 42)

      expect(result.urls).to eq(["https://external.example/path"])
    end

    it "checks clickable external links inside quotes but ignores the generated internal quote target" do
      analyzer = instance_double(PostAnalyzer)
      allow(PostAnalyzer).to receive(:new).and_return(analyzer)
      allow(analyzer).to receive(:cook).and_return(
        <<~HTML,
          <aside class="quote" data-topic="123" data-post="2">
            <a href="https://quoted.example/">Quoted link</a>
            <a href="/t/original-topic/123/2">Internal quote target</a>
            <aside class="onebox" data-onebox-src="https://quoted-onebox.example/"></aside>
          </aside>
        HTML
      )

      result = described_class.post_raw_result("raw", 42)

      expect(result.urls).to contain_exactly(
        "https://quoted.example/",
        "https://quoted-onebox.example/",
      )
    end

    it "preserves PostStripper semantics for ordinary links while retaining onebox sources" do
      analyzer = instance_double(PostAnalyzer)
      allow(PostAnalyzer).to receive(:new).and_return(analyzer)
      allow(analyzer).to receive(:cook).and_return(
        '<div class="plugin-hidden"><a href="https://hidden.example/">Hidden</a>' \
          '<aside class="onebox" data-onebox-src="https://hidden-onebox.example/"></aside></div>' \
          '<aside class="onebox" data-onebox-src="https://onebox.example/"></aside>' \
          '<a href="https://visible.example/">Visible</a>',
      )
      allow(PostStripper).to receive(:strip) do |doc|
        doc.css(".plugin-hidden, .onebox").remove
        doc
      end

      result = described_class.post_raw_result("raw", 42)

      expect(result.urls).to contain_exactly("https://onebox.example/", "https://visible.example/")
      expect(PostStripper).to have_received(:strip)
    end

    it "passes the acting user to Discourse cooking" do
      user = Fabricate(:user)
      analyzer = instance_double(PostAnalyzer)
      allow(PostAnalyzer).to receive(:new).with("raw", 42).and_return(analyzer)
      allow(analyzer).to receive(:cook).with("raw", topic_id: 42, user_id: user.id).and_return("<p>text</p>")

      described_class.post_raw_result("raw", 42, user: user)

      expect(analyzer).to have_received(:cook).with("raw", topic_id: 42, user_id: user.id)
    end
  end

  describe ".chat_message_result" do
    it "checks clickable external links inside Chat quotes" do
      allow(Chat::Message).to receive(:cook).and_return(
        '<aside class="quote" data-topic="123"><a href="https://quoted.example/">Quoted</a></aside>',
      )

      result = described_class.chat_message_result("quoted raw")

      expect(result.urls).to eq(["https://quoted.example/"])
    end

    it "uses the editor for cooking permissions without changing the original slash-command author" do
      author = Fabricate(:user)
      editor = Fabricate(:user)
      allow(Chat::Message).to receive(:cook).and_return('<a href="https://external.example/">External</a>')

      result = described_class.chat_message_result(
        "/me https://external.example/",
        user: editor,
        author_username: author.username,
      )

      expect(Chat::Message).to have_received(:cook).with(
        "/me https://external.example/",
        user_id: editor.id,
        author_username: author.username,
      )
      expect(result.urls).to eq(["https://external.example/"])
    end
  end
end
