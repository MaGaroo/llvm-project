//===- MarkupFilter.h -------------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
///
/// \file
/// This file declares a filter that replaces symbolizer markup with
/// human-readable expressions.
///
//===----------------------------------------------------------------------===//

#ifndef LLVM_DEBUGINFO_SYMBOLIZE_MARKUPFILTER_H
#define LLVM_DEBUGINFO_SYMBOLIZE_MARKUPFILTER_H

#include "Markup.h"

#include <map>

#include "llvm/ADT/DenseMap.h"
#include "llvm/Support/WithColor.h"
#include "llvm/Support/raw_ostream.h"

namespace llvm {
namespace symbolize {

class LLVMSymbolizer;

/// Filter to convert parsed log symbolizer markup elements into human-readable
/// text.
class MarkupFilter {
public:
  MarkupFilter(raw_ostream &OS, LLVMSymbolizer &Symbolizer,
               Optional<bool> ColorsEnabled = std::nullopt);

  /// Filters a line containing symbolizer markup and writes the human-readable
  /// results to the output stream.
  ///
  /// Invalid or unimplemented markup elements are removed. Some output may be
  /// deferred until future filter() or finish() call.
  void filter(StringRef Line);

  /// Records that the input stream has ended and writes any deferred output.
  void finish();

private:
  struct Module {
    uint64_t ID;
    std::string Name;
    SmallVector<uint8_t> BuildID;
  };

  struct MMap {
    uint64_t Addr;
    uint64_t Size;
    const Module *Mod;
    std::string Mode; // Lowercase
    uint64_t ModuleRelativeAddr;

    bool contains(uint64_t Addr) const;
    uint64_t getModuleRelativeAddr(uint64_t Addr) const;
  };

  // An informational module line currently being constructed. As many mmap
  // elements as possible are folded into one ModuleInfo line.
  struct ModuleInfoLine {
    const Module *Mod;

    SmallVector<const MMap *> MMaps = {};
  };

  // The semantics of a possible program counter value.
  enum class PCType {
    // The address is a return address and must be adjusted to point to the call
    // itself.
    ReturnAddress,
    // The address is the precise location in the code and needs no adjustment.
    PreciseCode,
  };

  bool tryContextualElement(const MarkupNode &Node,
                            const SmallVector<MarkupNode> &DeferredNodes);
  bool tryMMap(const MarkupNode &Element,
               const SmallVector<MarkupNode> &DeferredNodes);
  bool tryReset(const MarkupNode &Element,
                const SmallVector<MarkupNode> &DeferredNodes);
  bool tryModule(const MarkupNode &Element,
                 const SmallVector<MarkupNode> &DeferredNodes);

  void beginModuleInfoLine(const Module *M);
  void endAnyModuleInfoLine();

  void filterNode(const MarkupNode &Node);

  bool tryPresentation(const MarkupNode &Node);
  bool trySymbol(const MarkupNode &Node);
  bool tryPC(const MarkupNode &Node);
  bool tryBackTrace(const MarkupNode &Node);
  bool tryData(const MarkupNode &Node);

  bool trySGR(const MarkupNode &Node);

  void highlight();
  void highlightValue();
  void restoreColor();
  void resetColor();

  void printRawElement(const MarkupNode &Element);
  void printValue(Twine Value);

  Optional<Module> parseModule(const MarkupNode &Element) const;
  Optional<MMap> parseMMap(const MarkupNode &Element) const;

  Optional<uint64_t> parseAddr(StringRef Str) const;
  Optional<uint64_t> parseModuleID(StringRef Str) const;
  Optional<uint64_t> parseSize(StringRef Str) const;
  Optional<SmallVector<uint8_t>> parseBuildID(StringRef Str) const;
  Optional<std::string> parseMode(StringRef Str) const;
  Optional<PCType> parsePCType(StringRef Str) const;
  Optional<uint64_t> parseFrameNumber(StringRef Str) const;

  bool checkTag(const MarkupNode &Node) const;
  bool checkNumFields(const MarkupNode &Element, size_t Size) const;
  bool checkNumFieldsAtLeast(const MarkupNode &Element, size_t Size) const;
  bool checkNumFieldsAtMost(const MarkupNode &Element, size_t Size) const;

  void reportTypeError(StringRef Str, StringRef TypeName) const;
  void reportLocation(StringRef::iterator Loc) const;

  const MMap *getOverlappingMMap(const MMap &Map) const;
  const MMap *getContainingMMap(uint64_t Addr) const;

  uint64_t adjustAddr(uint64_t Addr, PCType Type) const;

  StringRef lineEnding() const;

  raw_ostream &OS;
  LLVMSymbolizer &Symbolizer;
  const bool ColorsEnabled;

  MarkupParser Parser;

  // Current line being filtered.
  StringRef Line;

  // A module info line currently being built. This incorporates as much mmap
  // information as possible before being emitted.
  Optional<ModuleInfoLine> MIL;

  // SGR state.
  Optional<raw_ostream::Colors> Color;
  bool Bold = false;

  // Map from Module ID to Module.
  DenseMap<uint64_t, std::unique_ptr<Module>> Modules;

  // Ordered map from starting address to mmap.
  std::map<uint64_t, MMap> MMaps;
};

} // end namespace symbolize
} // end namespace llvm

#endif // LLVM_DEBUGINFO_SYMBOLIZE_MARKUPFILTER_H
