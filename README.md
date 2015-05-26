# dexstrings
Extracting the strings from the .dex files with meaning.

Instead of using the typical 'strings' command on the .dex file, we can extract each string with some knowledge about what type of string is it.

You can request only the 'text strings', wich means only the strings that are not definied with other specific function as type, prototype, source or method name.

The approach is simple, but you can find interesting stuff in this piece of information. 
If the strings are in a different language (chinese, russian), you will need to have support for that encoding on your terminal to see them.

H.
