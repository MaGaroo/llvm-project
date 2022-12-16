//==- DebugCheckers.cpp - Debugging Checkers ---------------------*- C++ -*-==//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
//  This file defines checkers that display debugging information.
//
//===----------------------------------------------------------------------===//

#include "clang/StaticAnalyzer/Checkers/BuiltinCheckerRegistration.h"
#include "clang/Analysis/Analyses/Dominators.h"
#include "clang/Analysis/Analyses/LiveVariables.h"
#include "clang/Analysis/CallGraph.h"
#include "clang/StaticAnalyzer/Core/Checker.h"
#include "clang/StaticAnalyzer/Core/BugReporter/BugType.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/AnalysisManager.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/CheckerContext.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExplodedGraph.h"
#include "clang/StaticAnalyzer/Core/PathSensitive/ExprEngine.h"
#include "llvm/Support/Process.h"

using namespace clang;
using namespace ento;

//===----------------------------------------------------------------------===//
// DominatorsTreeDumper
//===----------------------------------------------------------------------===//

namespace {
class DominatorsTreeDumper : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager& mgr,
                        BugReporter &BR) const {
    if (AnalysisDeclContext *AC = mgr.getAnalysisDeclContext(D)) {
      CFGDomTree Dom;
      Dom.buildDominatorTree(AC->getCFG());
      Dom.dump();
    }
  }
};
}

void ento::registerDominatorsTreeDumper(CheckerManager &mgr) {
  mgr.registerChecker<DominatorsTreeDumper>();
}

bool ento::shouldRegisterDominatorsTreeDumper(const CheckerManager &mgr) {
  return true;
}

//===----------------------------------------------------------------------===//
// PostDominatorsTreeDumper
//===----------------------------------------------------------------------===//

namespace {
class PostDominatorsTreeDumper : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager& mgr,
                        BugReporter &BR) const {
    if (AnalysisDeclContext *AC = mgr.getAnalysisDeclContext(D)) {
      CFGPostDomTree Dom;
      Dom.buildDominatorTree(AC->getCFG());
      Dom.dump();
    }
  }
};
}

void ento::registerPostDominatorsTreeDumper(CheckerManager &mgr) {
  mgr.registerChecker<PostDominatorsTreeDumper>();
}

bool ento::shouldRegisterPostDominatorsTreeDumper(const CheckerManager &mgr) {
  return true;
}

//===----------------------------------------------------------------------===//
// ControlDependencyTreeDumper
//===----------------------------------------------------------------------===//

namespace {
class ControlDependencyTreeDumper : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager& mgr,
                        BugReporter &BR) const {
    if (AnalysisDeclContext *AC = mgr.getAnalysisDeclContext(D)) {
      ControlDependencyCalculator Dom(AC->getCFG());
      Dom.dump();
    }
  }
};
}

void ento::registerControlDependencyTreeDumper(CheckerManager &mgr) {
  mgr.registerChecker<ControlDependencyTreeDumper>();
}

bool ento::shouldRegisterControlDependencyTreeDumper(const CheckerManager &mgr) {
  return true;
}

//===----------------------------------------------------------------------===//
// LiveVariablesDumper
//===----------------------------------------------------------------------===//

namespace {
class LiveVariablesDumper : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager& mgr,
                        BugReporter &BR) const {
    if (LiveVariables* L = mgr.getAnalysis<LiveVariables>(D)) {
      L->dumpBlockLiveness(mgr.getSourceManager());
    }
  }
};
}

void ento::registerLiveVariablesDumper(CheckerManager &mgr) {
  mgr.registerChecker<LiveVariablesDumper>();
}

bool ento::shouldRegisterLiveVariablesDumper(const CheckerManager &mgr) {
  return true;
}

//===----------------------------------------------------------------------===//
// LiveStatementsDumper
//===----------------------------------------------------------------------===//

namespace {
class LiveExpressionsDumper : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager& Mgr,
                        BugReporter &BR) const {
    if (LiveVariables *L = Mgr.getAnalysis<RelaxedLiveVariables>(D))
      L->dumpExprLiveness(Mgr.getSourceManager());
  }
};
}

void ento::registerLiveExpressionsDumper(CheckerManager &mgr) {
  mgr.registerChecker<LiveExpressionsDumper>();
}

bool ento::shouldRegisterLiveExpressionsDumper(const CheckerManager &mgr) {
  return true;
}

//===----------------------------------------------------------------------===//
// CFGViewer
//===----------------------------------------------------------------------===//

namespace {
class CFGViewer : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager& mgr,
                        BugReporter &BR) const {
    if (CFG *cfg = mgr.getCFG(D)) {
      cfg->viewCFG(mgr.getLangOpts());
    }
  }
};
}

void ento::registerCFGViewer(CheckerManager &mgr) {
  mgr.registerChecker<CFGViewer>();
}

bool ento::shouldRegisterCFGViewer(const CheckerManager &mgr) {
  return true;
}

//===----------------------------------------------------------------------===//
// CFGDumper
//===----------------------------------------------------------------------===//

namespace {
class CFGDumper : public Checker<check::ASTCodeBody> {
public:
  void checkASTCodeBody(const Decl *D, AnalysisManager& mgr,
                        BugReporter &BR) const {
    PrintingPolicy Policy(mgr.getLangOpts());
    Policy.TerseOutput = true;
    Policy.PolishForDeclaration = true;
    D->print(llvm::errs(), Policy);

    if (CFG *cfg = mgr.getCFG(D)) {
      cfg->dump(mgr.getLangOpts(),
                llvm::sys::Process::StandardErrHasColors());
    }
  }
};
}

void ento::registerCFGDumper(CheckerManager &mgr) {
  mgr.registerChecker<CFGDumper>();
}

bool ento::shouldRegisterCFGDumper(const CheckerManager &mgr) {
  return true;
}

//===----------------------------------------------------------------------===//
// CallGraphViewer
//===----------------------------------------------------------------------===//

namespace {
class CallGraphViewer : public Checker< check::ASTDecl<TranslationUnitDecl> > {
public:
  void checkASTDecl(const TranslationUnitDecl *TU, AnalysisManager& mgr,
                    BugReporter &BR) const {
    CallGraph CG;
    CG.addToCallGraph(const_cast<TranslationUnitDecl*>(TU));
    CG.viewGraph();
  }
};
}

void ento::registerCallGraphViewer(CheckerManager &mgr) {
  mgr.registerChecker<CallGraphViewer>();
}

bool ento::shouldRegisterCallGraphViewer(const CheckerManager &mgr) {
  return true;
}

//===----------------------------------------------------------------------===//
// CallGraphDumper
//===----------------------------------------------------------------------===//

namespace {
class CallGraphDumper : public Checker< check::ASTDecl<TranslationUnitDecl> > {
public:
  void checkASTDecl(const TranslationUnitDecl *TU, AnalysisManager& mgr,
                    BugReporter &BR) const {
    CallGraph CG;
    CG.addToCallGraph(const_cast<TranslationUnitDecl*>(TU));
    CG.dump();
  }
};
}

void ento::registerCallGraphDumper(CheckerManager &mgr) {
  mgr.registerChecker<CallGraphDumper>();
}

bool ento::shouldRegisterCallGraphDumper(const CheckerManager &mgr) {
  return true;
}

//===----------------------------------------------------------------------===//
// ConfigDumper
//===----------------------------------------------------------------------===//

namespace {
class ConfigDumper : public Checker< check::EndOfTranslationUnit > {
  typedef AnalyzerOptions::ConfigTable Table;

  static int compareEntry(const Table::MapEntryTy *const *LHS,
                          const Table::MapEntryTy *const *RHS) {
    return (*LHS)->getKey().compare((*RHS)->getKey());
  }

public:
  void checkEndOfTranslationUnit(const TranslationUnitDecl *TU,
                                 AnalysisManager& mgr,
                                 BugReporter &BR) const {
    const Table &Config = mgr.options.Config;

    SmallVector<const Table::MapEntryTy *, 32> Keys;
    for (Table::const_iterator I = Config.begin(), E = Config.end(); I != E;
         ++I)
      Keys.push_back(&*I);
    llvm::array_pod_sort(Keys.begin(), Keys.end(), compareEntry);

    llvm::errs() << "[config]\n";
    for (unsigned I = 0, E = Keys.size(); I != E; ++I)
      llvm::errs() << Keys[I]->getKey() << " = "
                   << (Keys[I]->second.empty() ? "\"\"" : Keys[I]->second)
                   << '\n';
  }
};
}

void ento::registerConfigDumper(CheckerManager &mgr) {
  mgr.registerChecker<ConfigDumper>();
}

bool ento::shouldRegisterConfigDumper(const CheckerManager &mgr) {
  return true;
}

//===----------------------------------------------------------------------===//
// ExplodedGraph Viewer
//===----------------------------------------------------------------------===//

namespace {
class ExplodedGraphViewer : public Checker< check::EndAnalysis > {
public:
  ExplodedGraphViewer() {}
  void checkEndAnalysis(ExplodedGraph &G, BugReporter &B,ExprEngine &Eng) const {
    Eng.ViewGraph(false);
  }
};

}

void ento::registerExplodedGraphViewer(CheckerManager &mgr) {
  mgr.registerChecker<ExplodedGraphViewer>();
}

bool ento::shouldRegisterExplodedGraphViewer(const CheckerManager &mgr) {
  return true;
}

//===----------------------------------------------------------------------===//
// ConstraintExtractor
//===----------------------------------------------------------------------===//

#include <iostream>
using namespace std;

namespace {
class ConstraintExtractor : public Checker< check::EndAnalysis > {
public:
  unsigned int BlockID;

  ConstraintExtractor() {}

  void checkEndAnalysis(ExplodedGraph &G, BugReporter &B, ExprEngine &Eng) const {
    map<int64_t, map<int64_t, ProgramStateRef>> Constraints;
    for (ExplodedGraph::node_iterator I = G.nodes_begin(); I != G.nodes_end(); I++) {
      const ProgramPoint &PP = I->getLocation();
      if (PP.getKind() != ProgramPoint::BlockEdgeKind)
        continue;
      auto Edge = PP.castAs<BlockEdge>();
      if (Edge.getSrc()->getBlockID() != BlockID)
        continue;

      // Additional Checks
      // First, we check the preds size to not be more than 1
      if (I->pred_size() > 1) {
        cerr << "WARNING: check #1 failed at node " << I->getID() << '\n';
        return;
      }
      if (I->pred_size() == 0)
        return;

      // Second, we check the previous node to be post-statement
      // !!! This assumption is false, so its code is commented out !!!
      auto PredI = *I->pred_begin();
      /// if (PredI->getLocation().getKind() != ProgramPoint::PostStmtKind) {
      ///   cerr << "WARNING: check #2 failed at node " << I->getID() << '\n';
      ///   return;
      /// }

      // Third, we check PredI to have another predecessor
      if (PredI->pred_size() != 1) {
        cerr << "WARNING: check #3 failed at node " << I->getID() << '\n';
        return;
      }

      // Finally, we use the predecessor of PredI as the map's key
      auto PredPredI = *PredI->pred_begin();
      Constraints[PredPredI->getID()][Edge.getDst()->getBlockID()] = I->getState();

      // TODO
      // PROBLEM: how to find the exploded node before traversing the edge?
      // CURRENT SOLUTION: we use pred of pred of I, but it may be wrong
    }

    // Print the results
    for (auto const& [NodeId, Outgoing] : Constraints) {
      llvm::outs() << "Exploded Node ID: " << NodeId << "\n";
      for (auto const& [DestId, State] : Outgoing) {
        auto &CM = State->getConstraintManager();
        llvm::outs() << "    " << "From CFG Block " << BlockID << " to " << DestId << ":\n";
        CM.printJson(llvm::outs(), State, "\n", 4, false);
      }
      llvm::outs() << "=================\n";
    }
  }
};

}

void ento::registerConstraintExtractor(CheckerManager &mgr) {
  auto *Checker = mgr.registerChecker<ConstraintExtractor>();
  Checker->BlockID = mgr.getAnalyzerOptions().getCheckerIntegerOption(
      Checker, "BlockID");
}

bool ento::shouldRegisterConstraintExtractor(const CheckerManager &mgr) {
  return true;
}

//===----------------------------------------------------------------------===//
// Emits a report for every Stmt that the analyzer visits.
//===----------------------------------------------------------------------===//

namespace {

class ReportStmts : public Checker<check::PreStmt<Stmt>> {
  BuiltinBug BT_stmtLoc{this, "Statement"};

public:
  void checkPreStmt(const Stmt *S, CheckerContext &C) const {
    ExplodedNode *Node = C.generateNonFatalErrorNode();
    if (!Node)
      return;

    auto Report =
        std::make_unique<PathSensitiveBugReport>(BT_stmtLoc, "Statement", Node);

    C.emitReport(std::move(Report));
  }
};

} // end of anonymous namespace

void ento::registerReportStmts(CheckerManager &mgr) {
  mgr.registerChecker<ReportStmts>();
}

bool ento::shouldRegisterReportStmts(const CheckerManager &mgr) {
  return true;
}
