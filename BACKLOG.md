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

3. [High priority] Swap to blob storage for archived reading list items? It would be cool to have
   an actual archive of read articles somewhere, storing records for that may result in too many.
   This would involve making a new blob lexicon, it would store link, name, and shortened desc (100-120 chars?)
   Deleting from archive would remove from the blob, and adding to archive would add to the blob.
   Remove the archived field from the reading list item lexicon.

## Fixes
