
# GHOSTPARTY

 The program first prompts a menu 
 
 ![](https://hackmd.io/_uploads/HkYXomEC2.png)

There's some choice: `add`, `show`, `remove`, `night`, `end`

The challenge gives us a .cpp file

## Find bug


### Leak
* The first bug to leak libc and heap is in the `Alan` class

```cpp=
void addlightsaber(string str){
			lightsaber = (char*)str.c_str();		
		}
```

* This method, in paremeter `str` is a temporary variable and set `lightsaber` to `str.c_str()`
* I have the string object will be like

```
0                8
ptr              |size
capacity         
```

* The `str.c_str()` method return a pointer pointing to `capacity`

```cpp=
const _Elem *c_str() const _NOEXCEPT
    {   // return pointer to null-terminated nonmutable array
    return (this->_Myptr());
    }
```

* And since the `str` here is temporary, its destructor will be called after the function ends. The `capacity` field will be freed if the string object call `malloc` to allocate (this will happen when the string's len > `0x10`) so `lightsaber` points to a freed chunk
* Allocate a small chunk to leak heap
* Allocate a big chunk so that when freed it will be put in unsoterd bin to leak libc 

### Overwrite the class

There's some classes that doesn't meet the rule of three

[Rule of three](https://en.wikipedia.org/wiki/Rule_of_three_(C%2B%2B_programming))

> The Rule of Three suggests that if you need to define any of a copy constructor, copy assignment operator or destructor then you would usually need to define “all three”.

* Here i want to talk about having destructor but not copy constructor

[bug](http://www.fredosaurus.com/notes-cpp/oop-condestructors/copyconstructors.html#:~:text=If%20there%20is%20no%20copy,ie%2C%20makes%20a%20shallow%20copy.)

> If there is no copy constructor defined for the class, C++ uses the default copy constructor which copies each field, ie, makes a shallow copy.

* The interesting class is `Vampire`. It doesn't have a copy constructor but having a destructor

```cpp=
~Vampire(){
			delete[] blood;
		};
```

* So what a `shallow copy` means?

[shallow_copy](https://www.geeksforgeeks.org/shallow-copy-and-deep-copy-in-c/)

> In shallow copy, an object is created by simply copying the data of all variables of the original object. This works well if none of the variables of the object are defined in the heap section of memory. If some variables are dynamically allocated memory from heap section, then the copied object variable will also reference the same memory location.

* So let look in `Vampire` in `3` choice of `smallist`

```cpp=
case 3 :
			ghostlist.push_back(ghost);
			speaking(*ghost);
			cout << "\033[32mThe ghost is joining the party\033[0m" << endl ;
			return 1;
			break ;
```

* Notice here it calls `speaking(*ghost)`


```cpp=
template <class T>
void speaking(T ghost){
	ghost.speak();
};
```

* The `speak` method just print `msg` but `ghost` here is a temporary variable. It's a shallow copy of `Vampire` class before. So the `blood` pointer is the same, when the function ends, the destructor will free `blood` so the `Vampire` pushed to `vector` will have the freed `blood` field. And yeh i think this bug can leak libc too.
* After all we have `UAF` or `doubly-free` here

## Exploit

* After having a `Vampire` with a freed `blood` i create a new `ghost`, this `ghost` will reuse the freed `blood` chunk (remember to make `blood` size to get `0x70` chunk before)
* Then i delete the `Vampire` before so the last `ghost` will be a freed chunk. Allocating a new `Vampire` (or anything) which will use the freed chunk to overwrite it to craft the `vtable`
* But notice in `listghost` function


```cpp=
void listghost(){
	vector<Ghost*>::iterator iter;
	int i = 0 ;
	for(iter = ghostlist.begin() ; iter != ghostlist.end() ; iter++,i++){
		cout << i << ". " ;
		cout <<  (**iter).gettype() << " : " << (**iter).getname() << endl;

	}	
	cout << endl ;
}
```

* We have to craft a valid `type` and `name` field, othewise it will throw a `std::bad_alloc` exception
* After that the program calls `ghostinfo` method which is a virtual function so the program will use `vtable` to call


```cpp=
int showinfo(){
	unsigned int ghostindex ;
	if(ghostlist.size() == 0){
		cout << "\033[31mNo ghost in the party\033[0m " << endl ;
		return 0 ;
	}
	cout << "Choose a ghost which you want to show in the party : " ;
	cin >> ghostindex ;
	if(ghostindex >= ghostlist.size()){
		cout << "\033[31mInvaild index\033[0m" << endl ;
		return 0 ;
	}
	cout << ">-----GHOST INFO-----<" << endl;
	ghostlist[ghostindex]->ghostinfo();
	return 1 ;
}
```

* The `ghostinfo` method is at `*(vtable + 0x10)`. Overwrite it with `one_gadget` to get a shell
* My crafted chunk

![](https://hackmd.io/_uploads/HJuD7VNC3.jpg)

![](https://hackmd.io/_uploads/S1l_mNV02.png)
