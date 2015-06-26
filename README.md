# dexstrings
Extracting the strings from the .dex files with meaning.

Instead of using the typical 'strings' command on the .dex file, we can extract each string with some knowledge about what type of string is it.

You can request only the 'text strings', wich means only the strings that are not definied with other specific function as type, prototype, source or method name.

The approach is simple, but you can find interesting stuff in this piece of information. 
If the strings are in a different language (chinese, russian), you will need to have support for that encoding on your terminal to see them.

H.

## Changelog
###0.8
New options added: -u -r -s

  -u

  Unicode string detection added in a very naive way, comparing the number of characters vs the number of utf8 characters.
  If the string is only one character it does not detect it.

  -r

  print the number of references to that string in the rest of the tables

  -s

  print the size in characters and in utf8_characters.

Separator changed to |. 
