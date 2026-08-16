# frozen_string_literal: true

class AddSourceProviderToLinkSafetyCacheEntries < ActiveRecord::Migration[7.0]
  def up
    unless column_exists?(:link_safety_cache_entries, :source_provider)
      add_column :link_safety_cache_entries, :source_provider, :string, limit: 32
    end

    execute <<~SQL
      UPDATE link_safety_cache_entries
      SET source_provider = provider
      WHERE source_provider IS NULL OR source_provider = ''
    SQL
    change_column_null :link_safety_cache_entries, :source_provider, false
  end

  def down
    remove_column :link_safety_cache_entries, :source_provider if column_exists?(:link_safety_cache_entries, :source_provider)
  end
end
