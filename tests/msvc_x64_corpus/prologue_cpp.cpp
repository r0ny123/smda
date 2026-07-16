class Base {
public:
    virtual int transform(int value) const {
        return value + 2;
    }
};

class Derived : public Base {
public:
    int transform(int value) const override {
        return value * 5;
    }
};

__declspec(noinline) int cpp_virtual(const Base& object, int value) {
    return object.transform(value);
}

__declspec(noinline) int cpp_stack(int seed) {
    volatile unsigned char buffer[1024];
    int value = seed;
    for (int index = 0; index < (int)sizeof(buffer); index++) {
        buffer[index] = (unsigned char)(value + index);
        value ^= buffer[index];
    }
    return value;
}

__declspec(noinline) int cpp_exception(int value) {
    try {
        if (value < 0) {
            throw value;
        }
        return value + 11;
    } catch (int error) {
        return error - 11;
    }
}

__declspec(noinline) int cpp_reference(int& value) {
    value += 13;
    return value;
}

int main() {
    Derived object;
    int value = cpp_stack(9);
    return cpp_virtual(object, value) + cpp_exception(value) + cpp_reference(value);
}
