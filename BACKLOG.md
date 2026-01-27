## Description

This file includes the backlog of features and fixes that need to be done.
Each should be addressed one at a time, and the item should be removed after implementation has been finished and verified.

---

## Features

1. [Low prio, do later] PDS blobs are not allowed to be bigger than 1MB, which we probably shouldn't get to
   with what we are storing, but it would be prudent to check size of the data stored,
   breaking out into multiple blobs if necessary. The home page fetcher would need to
   fetch all blobs of the feedCache type from the user (or feedcache would be able to
   reference multiple blobs).

2. [medium priority] Store more than 200 feed entries in blob. We have plenty of storage room, and there
   isn't really a downside since we already fetch the entire rss feed anyway.

3. [Future work] scroll to top with pull down on mobile or page refresh (maybe not page refresh) should refresh browser cache of feed data. This may be a bit weird since this isn't a native app -- cross-device syncing could probably be handled differently

4. cross-compatability with margin.at bookmark lexicon (for reading list)
   - Allow import bookmarks or just auto-import?

- Switch to/add support for importing standard.site lexicon subscriptions
  - I think leaflet switched to this

- Allow editing a reading list item, editing title, link, etc

## Fixes

- Homepage feed fetches/blob uploads seem to fail pretty frequently, but log messages are not clear as to why this is happening

- Removed list does not seem to be respected by the homepage

- Duplicates are allowed in the reading list, archive, and removed list

- Trim down bottom margin of reading list items
