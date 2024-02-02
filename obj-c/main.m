//
//  main.m
//  dylibify
//
//  Created by Jake James on 7/13/18.
//  Copyright © 2018 Jake James. All rights reserved.
//
// clang -o dylibify main.m dylibify.m -framework Foundation -fobjc-arc

#include <Foundation/Foundation.h>
#include "./dylibify.h"

int main(int argc, const char **argv) {
    NSDictionary *args =
        [[NSUserDefaults standardUserDefaults] volatileDomainForName:NSArgumentDomain];

    NSString *infile = args[@"in"];
    NSString *outfile = args[@"out"];

    if (!infile || !outfile) {
        printf("Usage:\n\t%s -in <in> -out <out>\nExample:\n\t%s -in /usr/bin/executable -out "
               "/usr/lib/dylibified.dylib\n",
               argv[0], argv[0]);
        return -1;
    }

    NSError *error;
    dylibify(infile, outfile, &error);

    if (error) {
        printf("Couldn't dylibify file: %s", error.description.UTF8String);
        return 1;
    }

    return 0;
}
