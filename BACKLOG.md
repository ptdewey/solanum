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

## Bugs

(none currently)
