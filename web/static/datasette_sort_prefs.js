// Persist Datasette sort preferences in localStorage
(function () {
  var path = location.pathname;
  // Match table pages: /database/table
  var parts = path.replace(/^\/+|\/+$/g, "").split("/");
  if (parts.length !== 2) return;

  var key = "datasette_sort:" + parts[0] + "/" + parts[1];
  var params = new URLSearchParams(location.search);

  var hasSort = params.has("_sort") || params.has("_sort_desc");

  if (hasSort) {
    // Save current sort to localStorage
    var pref = {};
    if (params.has("_sort")) pref._sort = params.get("_sort");
    if (params.has("_sort_desc")) pref._sort_desc = params.get("_sort_desc");
    localStorage.setItem(key, JSON.stringify(pref));
  } else {
    // No sort in URL — restore from localStorage if available
    var saved = localStorage.getItem(key);
    if (saved) {
      try {
        var pref = JSON.parse(saved);
        if (pref._sort) params.set("_sort", pref._sort);
        if (pref._sort_desc) params.set("_sort_desc", pref._sort_desc);
        // Only redirect if we actually added sort params
        if (params.has("_sort") || params.has("_sort_desc")) {
          location.replace(path + "?" + params.toString());
        }
      } catch (e) {
        localStorage.removeItem(key);
      }
    }
  }
})();
