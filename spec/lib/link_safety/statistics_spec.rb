# frozen_string_literal: true

RSpec.describe LinkSafety::Statistics do
  before do
    LinkSafety::DailyStat.delete_all
  end

  it "persists ordinary counters" do
    described_class.bump!("safe_browsing_v5", checks: 2, provider_calls: 1, threats: 1, monitored: 1)

    row = LinkSafety::DailyStat.find_by!(stat_date: Date.current, provider: "safe_browsing_v5")
    expect(row.checks).to eq(2)
    expect(row.provider_calls).to eq(1)
    expect(row.threats).to eq(1)
    expect(row.monitored).to eq(1)
  end

  it "maps the public errors counter to the ActiveRecord-safe error_count column" do
    described_class.bump!("safe_browsing_v5", errors: 2)

    row = LinkSafety::DailyStat.find_by!(stat_date: Date.current, provider: "safe_browsing_v5")
    expect(row.error_count).to eq(2)
  end
end

RSpec.describe "LinkSafety::Statistics capture" do
  before do
    LinkSafety::DailyStat.delete_all
  end

  it "buffers counters until the snapshot is applied" do
    _value, snapshot = LinkSafety::Statistics.capture do
      LinkSafety::Statistics.bump!("safe_browsing_v5", checks: 2, provider_calls: 1, errors: 1)
    end

    expect(LinkSafety::DailyStat.count).to eq(0)

    LinkSafety::Statistics.apply_snapshot!(snapshot)
    row = LinkSafety::DailyStat.find_by!(stat_date: Date.current, provider: "safe_browsing_v5")
    expect(row.checks).to eq(2)
    expect(row.provider_calls).to eq(1)
    expect(row.error_count).to eq(1)
  end
end

RSpec.describe "LinkSafety::Statistics transaction finalization" do
  class LinkSafetyStatisticsFakeTransaction
    attr_reader :commit_callbacks, :rollback_callbacks

    def initialize
      @commit_callbacks = []
      @rollback_callbacks = []
    end

    def open? = true
    def after_commit(&block) = @commit_callbacks << block
    def after_rollback(&block) = @rollback_callbacks << block
  end

  class LinkSafetyStatisticsTransactionModel
    class << self
      attr_accessor :test_transaction

      def current_transaction = test_transaction
    end
  end

  before do
    LinkSafety::DailyStat.delete_all
  end

  it "persists captured counters after rollback instead of inside validation" do
    transaction = LinkSafetyStatisticsFakeTransaction.new
    LinkSafetyStatisticsTransactionModel.test_transaction = transaction
    model = LinkSafetyStatisticsTransactionModel.new

    _value, snapshot = LinkSafety::Statistics.capture do
      LinkSafety::Statistics.bump!("safe_browsing_v5", checks: 1, provider_calls: 1, threats: 1, blocked: 1)
    end

    result = LinkSafety::Statistics.finalize_capture!(model, snapshot)
    expect(result).to eq(:registered)
    expect(LinkSafety::DailyStat.count).to eq(0)

    transaction.rollback_callbacks.each(&:call)

    row = LinkSafety::DailyStat.find_by!(stat_date: Date.current, provider: "safe_browsing_v5")
    expect(row.checks).to eq(1)
    expect(row.provider_calls).to eq(1)
    expect(row.threats).to eq(1)
    expect(row.blocked).to eq(1)
  ensure
    LinkSafetyStatisticsTransactionModel.test_transaction = nil
  end
end
