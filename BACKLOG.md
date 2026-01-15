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

2. [High priority] Allow removing from the home feed page. This will require making a new blob that
   stores removed entries. This one could be optimized by storing minimal information
   (probably just the url to be able to identify it and filter out of fetches).
   With this, I would also want to be able to tag entries from the homepage as read,
   which would add them to the new blob as well as creating a reading list entry
   that is archived immediately.
   The home page entries blob would explicitly not include entries from the removed
   feed items blob.

3. [medium priority] Store more than 200 feed entries in blob. We have plenty of storage room, and there
   isn't really a downside since we already fetch the entire rss feed anyway.

## Fixes
