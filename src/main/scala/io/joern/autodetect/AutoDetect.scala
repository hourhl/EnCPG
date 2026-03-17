package io.joern.autodetect

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.passes.CpgPass
import flatgraph.DiffGraphBuilder
import io.shiftleft.semanticcpg.layers.{
  LayerCreator,
  LayerCreatorContext,
  LayerCreatorOptions
}
import io.shiftleft.semanticcpg.language._
import java.io.PrintWriter
import scala.util.{Try, Success, Failure}

object AutoDetect {

  /**
    * This is the extension's official name as shown in the table
    * obtained when running `run` on the Joern shell.
    */
  val overlayName = "Auto Detect"

  /**
    * A short description shown in the table obtained when
    * running `run` on the Joern shell.
    */
  val description =
    "Auto detect vulnerabilities from extended cpg"

  /**
    * Default options initialized to defaults. This object will be made
    * accessible to the user via `opts.autodetect`.
    */
  def defaultOpts = AutoDetectOpts("")
}

/**
  * Options can be passed to the extension via a custom options
  * class that derives from `LayerCreatorOptions`.
  */
case class AutoDetectOpts(var outputPath: String = "")
    extends LayerCreatorOptions {}

class AutoDetect(options: AutoDetectOpts) extends LayerCreator {
  override val overlayName: String = AutoDetect.overlayName
  override val description: String = AutoDetect.description

  /**
    * This method is executed when the user issues the command
    * `run.autodetect`.
    */
  override def create(context: LayerCreatorContext): Unit = {
    val cpg = context.cpg
    new VulnerabilityDetectionPass(cpg).createAndApply()
  }

  private class VulnerabilityDetectionPass(cpg: Cpg) extends CpgPass(cpg) {
    // Comparison operator names used in vulnerability detection
    private val comparisonOperators = Set(
      "<operator>.lessThan",
      "<operator>.greaterThan",
      "<operator>.lessEqualsThan",
      "<operator>.greaterEqualsThan"
    )
    
    // Dangerous functions that can cause null pointer dereference
    // Map: function name -> list of parameter positions to check (1-indexed)
    private val dangerousFuncs = Map(
      "strlen" -> List(1),
      "strcpy" -> List(1, 2),
      "strncpy" -> List(1, 2),
      "strcat" -> List(1, 2),
      "strcmp" -> List(1, 2),
      "strncmp" -> List(1, 2),
      "strncasecmp" -> List(1, 2),
      "strstr" -> List(1, 2),
      "strchr" -> List(1),
      "strdup" -> List(1),
      "memcpy" -> List(1, 2),
      "memset" -> List(1),
      "memcmp" -> List(1, 2),
      "memmove" -> List(1, 2),
      "printf" -> List(1),
      "sprintf" -> List(1, 2),
      "puts" -> List(1),
      "fputs" -> List(1)
    )
    
    // Null pointer literals to check for
    private val nullLiterals = Set("0", "0LL")
    
    // Integer types prone to overflow vulnerabilities
    // These types are commonly used in arithmetic operations that can overflow
    private val overflowProneTypes = Set(
      // Unsigned integer types
      "unsigned", "unsigned int", "unsigned long", "unsigned long long",
      "uint8_t", "uint16_t", "uint32_t", "uint64_t",
      // Signed integer types
      "int", "long", "long long",
      "int8_t", "int16_t", "int32_t", "int64_t",
      // Size-related types
      "size_t", "ssize_t", "off_t", "ptrdiff_t"
    )
    
    override def run(builder: DiffGraphBuilder): Unit = {
      println("[*] Starting vulnerability detection on traced methods...")
      
      // Find methods that have been traced (BeenTraced = true)
      val tracedMethods = cpg.method.has("BeenTraced").l
      println(s"[*] Found ${tracedMethods.size} traced methods")

      // Vul type 1 : buffer overflow
      println("[*] Vul type 1 : buffer overflow")
      
      // 1.1 memcpy
      // For each traced method, check for vulnerable memcpy patterns
      println("[*] 1.1 memcpy analysis")
      val memcpy_vulnerabilities = tracedMethods.flatMap { method =>
        val vulnerableMemcpy = findVulnerableMemcpy(method)
        if (vulnerableMemcpy.nonEmpty) {
          println(s"\n[!] Vulnerable method found: ${method.name}")
          vulnerableMemcpy.foreach { memcpyCall =>
            val code = memcpyCall.code
            val lineNumber = memcpyCall.lineNumber.getOrElse(-1)
            println(s"    - memcpy call: $code")
            println(s"    - Line number: $lineNumber")
          }
        }
        vulnerableMemcpy.map { call =>
          s"Method: ${method.name}, Function: memcpy, Line: ${call.lineNumber.getOrElse(-1)}, Call: ${call.code}"
        }
      }
      
      // 1.2 strncpy, memcpy and similar copy functions
      // Check for vulnerable copy patterns
      println("[*] 1.2 copy functions (strncpy, memcpy, memmove) analysis")
      val cpy_vulnerabilities = tracedMethods.flatMap { method =>
        val vulnerableStrncpy = findVulnerablewithcpy(method)
        if (vulnerableStrncpy.nonEmpty) {
          println(s"\n[!] Vulnerable copy function method found: ${method.name}")
          vulnerableStrncpy.foreach { copyCall =>
            val code = copyCall.code
            val lineNumber = copyCall.lineNumber.getOrElse(-1)
            val funcName = copyCall.name
            println(s"    - $funcName call: $code")
            println(s"    - Line number: $lineNumber")
          }
        }
        vulnerableStrncpy.map { call =>
          s"Method: ${method.name}, Function: ${call.name}, Line: ${call.lineNumber.getOrElse(-1)}, Call: ${call.code}"
        }
      }

      // 1.3 off by one
      println("[*] 1.3 off by one analysis")
      val offByOneVulnerabilities = detectOffByOne(tracedMethods)
      if (offByOneVulnerabilities.nonEmpty) {
        println(s"[!] Found ${offByOneVulnerabilities.size} off-by-one vulnerabilities")
        offByOneVulnerabilities.foreach { case (methodName, checkFunc, checkLine, checkCode, writeFunc, writeLine, writeCode) =>
          println(s"    Method: $methodName")
          println(s"    Check: $checkCode (line $checkLine)")
          println(s"    Write: $writeCode (line $writeLine)")
        }
      } else {
        println("[+] No off-by-one vulnerabilities detected")
      }
      
      // Vul type 2: null pointer dereference
      println("[*] Vul type 2: null pointer dereference")
      
      // 2.1 dangerous function calls without null check
      println("[*] 2.1 dangerous function calls without null check")
      val nullPtrVulnerabilities = detectNullPointerDereference(tracedMethods)
      
      if (nullPtrVulnerabilities.nonEmpty) {
        println(s"[!] Found ${nullPtrVulnerabilities.size} null pointer dereference vulnerabilities (function calls)")
        nullPtrVulnerabilities.foreach { case (methodName, funcName, param, pos, code, line) =>
          println(s"    Method: $methodName, Function: $funcName, Parameter: $param (pos $pos), Line: $line")
          println(s"    Code: $code")
        }
      } else {
        println("[+] No null pointer dereference vulnerabilities detected (function calls)")
      }
      
      // 2.2 struct field access without null check
      println("[*] 2.2 struct field access without null check")
      val fieldAccessVulnerabilities = detectFieldAccessWithoutNullCheck(tracedMethods)
      
      if (fieldAccessVulnerabilities.nonEmpty) {
        println(s"[!] Found ${fieldAccessVulnerabilities.size} field access without null check vulnerabilities")
        fieldAccessVulnerabilities.take(10).foreach { case (methodName, lineNo, objectName, fieldAccessCode) =>
          println(f"    [!] 漏洞 L$lineNo%5d: $objectName->... ($fieldAccessCode)")
        }
      } else {
        println("[+] No field access without null check vulnerabilities detected")
      }
      
      // Vul type 3: use after free
      println("[*] Vul type 3: use after free")
      val useAfterFreeVulnerabilities = detectUseAfterFree(tracedMethods)
      
      if (useAfterFreeVulnerabilities.nonEmpty) {
        println(s"[!] Found ${useAfterFreeVulnerabilities.size} use after free vulnerabilities")
        useAfterFreeVulnerabilities.foreach { case (file, func, ptrLine, ptrCode, var_, freeLine, freeCode, useLine, useCode, freeArg) =>
          println(s"    File: $file, Method: $func")
          println(s"    Pointer assignment (line $ptrLine): $ptrCode")
          println(s"    Free call (line $freeLine): $freeCode")
          println(s"    Use after free (line $useLine): $useCode")
        }
      } else {
        println("[+] No use after free vulnerabilities detected")
      }
      
      // Vul type 3: command execution
      println("[*] Vul type 3: command execution")
      val cmdExecVulnerabilities = detectCommandExecution(tracedMethods)
      
      if (cmdExecVulnerabilities.nonEmpty) {
        println(s"[!] Found ${cmdExecVulnerabilities.size} command execution vulnerabilities")
        cmdExecVulnerabilities.foreach { case (methodName, systemCode, systemLine, taintedParams, sprintfLine) =>
          println(s"    Method: $methodName")
          println(s"    System Call: $systemCode (Line: $systemLine)")
          println(s"    Tainted Parameters: $taintedParams (Line: $sprintfLine)")
        }
      } else {
        println("[+] No command execution vulnerabilities detected")
      }

      // Vul type 4: integer overflow
      println("[*] Vul type 4: integer overflow")
      // 4.1 multiple arithmetic operations without proper checks
      val integerOverflowVulnerabilities = detectIntegerOverflow(tracedMethods)
      
      if (integerOverflowVulnerabilities.nonEmpty) {
        println(s"[!] Found ${integerOverflowVulnerabilities.size} integer overflow vulnerabilities")
        integerOverflowVulnerabilities.foreach { case (methodName, lineNo, code) =>
          println(s"    Method: $methodName, Line: $lineNo")
          println(s"    Code: $code")
        }
      } else {
        println("[+] No integer overflow vulnerabilities detected")
      }

      // 4.2 arithmetic operations without proper checks before realloc
      println("[*] 4.2 realloc with integer overflow risk")
      val reallocIntOverflowVulnerabilities = detectReallocIntegerOverflow(tracedMethods)
      
      if (reallocIntOverflowVulnerabilities.nonEmpty) {
        println(s"[!] Found ${reallocIntOverflowVulnerabilities.size} realloc integer overflow vulnerabilities")
        reallocIntOverflowVulnerabilities.foreach { case (methodName, reallocLine, reallocCode, assignLine, assignCode) =>
          println(s"    Method: $methodName")
          println(s"    Assignment: $assignCode (Line: $assignLine)")
          println(s"    Realloc: $reallocCode (Line: $reallocLine)")
        }
      } else {
        println("[+] No realloc integer overflow vulnerabilities detected")
      }
      
      // Collect all vulnerabilities
      val nullptrStrings = nullPtrVulnerabilities.map { case (methodName, funcName, param, pos, code, line) =>
        s"Method: $methodName, Function: $funcName, Line: $line, Call: $code"
      }
      
      val cmdExecStrings = cmdExecVulnerabilities.map { case (methodName, systemCode, systemLine, taintedParams, sprintfLine) =>
        s"Method: $methodName\n  System Call: $systemCode (Line: $systemLine)\n  Tainted Parameters: $taintedParams (Line: $sprintfLine)"
      }
      
      val fieldAccessVulStrings = fieldAccessVulnerabilities.map { case (methodName, lineNo, objectName, fieldAccessCode) =>
        s"Method: $methodName, Line: $lineNo, Code: $fieldAccessCode"
      }
      
      val useAfterFreeStrings = useAfterFreeVulnerabilities.map { case (file, func, ptrLine, ptrCode, var_, freeLine, freeCode, useLine, useCode, freeArg) =>
        s"Method: $func, Line: $useLine, Code: $useCode (freed at line $freeLine)"
      }
      
      val offByOneStrings = offByOneVulnerabilities.map { case (methodName, checkFunc, checkLine, checkCode, writeFunc, writeLine, writeCode) =>
        s"Method: $methodName, Function: $writeFunc, Line: $writeLine, Code: $writeCode (check at line $checkLine: $checkCode)"
      }
      
      val integerOverflowStrings = integerOverflowVulnerabilities.map { case (methodName, lineNo, code) =>
        s"Method: $methodName, Line: $lineNo, Code: $code"
      }
      
      val reallocIntOverflowStrings = reallocIntOverflowVulnerabilities.map { case (methodName, reallocLine, reallocCode, assignLine, assignCode) =>
        s"Method: $methodName, Realloc Line: $reallocLine, Code: $reallocCode (size from line $assignLine: $assignCode)"
      }
      
      val allVulnerabilities = Map.empty[String, List[String]] ++
        (if (memcpy_vulnerabilities.nonEmpty) Map("Buffer Overflow (dest offset too big)" -> memcpy_vulnerabilities.toList) else Map.empty) ++
        (if (cpy_vulnerabilities.nonEmpty) Map("Buffer Overflow (cpy without check)" -> cpy_vulnerabilities.toList) else Map.empty) ++
        (if (offByOneStrings.nonEmpty) Map("Off By One" -> offByOneStrings) else Map.empty) ++
        // (if (vulStrings.nonEmpty) Map("Null Pointer Dereference" -> vulStrings) else Map.empty) ++
        (if (cmdExecStrings.nonEmpty) Map("Command Execution" -> cmdExecStrings) else Map.empty) ++
        (if (nullptrStrings.nonEmpty) Map("Null Pointer Dereference (Function Call)" -> nullptrStrings) else Map.empty) ++
        (if (fieldAccessVulStrings.nonEmpty) Map("Null Pointer Dereference (Field Access)" -> fieldAccessVulStrings) else Map.empty) ++
        (if (useAfterFreeStrings.nonEmpty) Map("Use After Free" -> useAfterFreeStrings) else Map.empty) ++
        (if (integerOverflowStrings.nonEmpty) Map("Integer Overflow" -> integerOverflowStrings) else Map.empty) ++
        (if (reallocIntOverflowStrings.nonEmpty) Map("Integer Overflow in Realloc" -> reallocIntOverflowStrings) else Map.empty)
      
      // Write results to file if outputPath is specified
      if (options.outputPath.nonEmpty) {
        writeVulnerabilitiesToFile(allVulnerabilities, options.outputPath)
      } else {
        println("[!] No output path specified. Use opts.autodetect.outputPath = \"/path/to/VulReport.txt\"")
      }
      
      // Summary
      val totalVulnerabilities = allVulnerabilities.values.map(_.size).sum
      if (totalVulnerabilities == 0) {
        println("\n[+] No vulnerabilities detected")
      } else {
        println(s"\n[!] Total vulnerabilities found: $totalVulnerabilities")
        allVulnerabilities.foreach { case (category, vulns) =>
          println(s"    - $category: ${vulns.size}")
        }
      }
    }
    
    /**
      * Detects null pointer dereference vulnerabilities in traced methods.
      * Returns a list of tuples: (methodName, functionName, paramName, position, code, lineNumber)
      */
    private def detectNullPointerDereference(tracedMethods: List[io.shiftleft.codepropertygraph.generated.nodes.Method]): List[(String, String, String, Int, String, Int)] = {
      val tracedMethodsfilter = tracedMethods.filterNot(_.name == "<global>")
      tracedMethodsfilter.flatMap { m =>
        // Cache AST nodes once per method for performance and deduplication
        val allCalls = m.ast.isCall.l
        val allCtrls = m.ast.isControlStructure.l
        
        // Collect pointer-type function parameters that might be NULL
        val funcParamVars = m.parameter
          .filter(p => p.typeFullName.contains("*"))
          .name.toSet
        
        // Track already-reported variables to deduplicate: only report the first
        // dangerous call involving each variable per method.
        val reportedVars = scala.collection.mutable.Set[String]()
        
        // Process dangerous calls sorted by line so deduplication keeps the earliest hit
        val dangerousCalls = allCalls
          .filter(c => dangerousFuncs.contains(c.name))
          .sortBy(_.lineNumber.getOrElse(0))
        
        dangerousCalls.flatMap { call =>
          val callLine = call.lineNumber.getOrElse(Int.MaxValue)
          
          // Locally-assigned variables before this call
          val localVarsBeforeCall = allCalls
            .filter(c => c.name == "<operator>.assignment" && c.lineNumber.exists(_ < callLine))
            .flatMap { assignment =>
              assignment.argument.order(1).headOption.map(_.code)
            }
            .toSet
          
          // Include pointer-type function parameters alongside local variables
          val candidateVars = localVarsBeforeCall ++ funcParamVars
          
          dangerousFuncs(call.name).flatMap { pos =>
            call.argument.order(pos).headOption.flatMap { argNode =>
              candidateVars.find(v => argNode.code == v).flatMap { variable =>
                if (reportedVars.contains(variable)) {
                  None
                } else {
                  val line = call.lineNumber.getOrElse(Int.MaxValue)
                  // Include same-line nodes (<= line) to catch guards like `ptr && func(ptr)`
                  val hasCheck = allCalls.filter(_.lineNumber.exists(_ <= line)).exists { c =>
                    val args = c.argument.code.l
                    (c.name == "<operator>.logicalNot" && args.contains(variable)) ||
                    // Logical-AND short-circuit: `ptr && func(ptr)` — non-null on RHS
                    (c.name == "<operator>.logicalAnd" && args.contains(variable)) ||
                    (c.name == "<operator>.equals" && args.contains(variable) && args.exists(nullLiterals.contains)) ||
                    (c.name == "<operator>.notEquals" && args.contains(variable) && args.exists(nullLiterals.contains))
                  } || allCtrls.filter(_.lineNumber.exists(_ <= line)).exists { ctrl =>
                    val cond = ctrl.condition.code.headOption.getOrElse("")
                    cond == variable || cond.matches(s".*\\b$variable\\b.*")
                  }
                  if (!hasCheck) {
                    reportedVars += variable
                    Some((m.name, call.name, variable, pos, call.code, call.lineNumber.getOrElse(-1)))
                  } else None
                }
              }
            }
          }
        }
      }
    }
    
    /**
      * Detects command execution vulnerabilities in traced methods.
      * Returns a list of tuples: (methodName, systemCode, systemLine, taintedParams, sprintfLine)
      * 
      * Detection logic:
      * 1. Find system() calls
      * 2. Check if system's argument can reach from sprintf's first argument (destination buffer)
      * 3. Check if sprintf's 3rd+ parameters come from user input (method parameters)
      * 4. Check if there's no security validation (e.g., command sanitization)
      */
    private def detectCommandExecution(tracedMethods: List[io.shiftleft.codepropertygraph.generated.nodes.Method]): List[(String, String, Int, String, Int)] = {
      val tracedMethodsfilter = tracedMethods.filterNot(_.name == "<global>")
      tracedMethodsfilter.flatMap { method =>
        // Get all system() calls in this method
        val systemCalls = method.ast.isCall.name("system").l
        
        systemCalls.flatMap { systemCall =>
          // Get the first argument of system() - the command string
          systemCall.argument.order(1).headOption match {
            case Some(sysArg) =>
              // Find sprintf calls in the same method
              val sprintfCalls = method.ast.isCall.name("sprintf").l
              
              // Check if system's argument can be reached from sprintf's destination
              // Since reachableBy API is not available, we use a heuristic:
              // Check if both system and sprintf reference the same variable
              val reachableSprintfCalls = sprintfCalls.filter { sprintfCall =>
                sprintfCall.argument.order(1).headOption match {
                  case Some(dest) =>
                    // Check if system argument references the same variable as sprintf destination
                    // Extract variable names from both
                    val sysVarOpt = extractVariableName(sysArg.code)
                    val destVarOpt = extractVariableName(dest.code)
                    
                    val isReachable = (sysVarOpt, destVarOpt) match {
                      case (Some(sysVar), Some(destVar)) => sysVar == destVar
                      case _ => false
                    }
                    
                    if (isReachable) {
                      // Additionally check the line numbers to ensure sprintf comes before system
                      // If line numbers are not available, we still consider it reachable
                      val sprintfLine = sprintfCall.lineNumber.getOrElse(Int.MaxValue)
                      val systemLine = systemCall.lineNumber.getOrElse(Int.MaxValue)
                      sprintfLine < systemLine
                    } else {
                      false
                    }
                  case None => false
                }
              }
              
              // For each reachable sprintf, check if it uses user input without validation
              reachableSprintfCalls.flatMap { sprintfCall =>
                val hasUserInput = checkSprintfUserInput(method, sprintfCall)
                val hasValidation = checkSecurityValidation(method, systemCall)
                
                if (hasUserInput && !hasValidation) {
                  val systemLine = systemCall.lineNumber.getOrElse(-1)
                  val sprintfLine = sprintfCall.lineNumber.getOrElse(-1)
                  // Get only the tainted parameters instead of full sprintf code
                  val taintedParams = getTaintedSprintfParameters(method, sprintfCall)
                  val taintedParamsStr = taintedParams.mkString(", ")
                  List((method.name, systemCall.code, systemLine, taintedParamsStr, sprintfLine))
                } else {
                  List.empty
                }
              }
            case None => List.empty
          }
        }
      }
    }
    
    /**
      * Checks if sprintf call uses user input in 3rd+ arguments.
      * User input is defined as:
      * 1. Variables obtained from sub_422EB8 function calls
      * 2. Variables derived through sub_406BB8 function from user input variables
      */
    private def checkSprintfUserInput(method: io.shiftleft.codepropertygraph.generated.nodes.Method, sprintfCall: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
      // Build set of tainted variables (user input sources)
      val taintedVars = buildTaintedVariables(method)
      
      // Get sprintf arguments from position 3 onwards (format string is at position 2)
      // Arguments start from 1, so 3+ means the format arguments/values for sprintf
      val sprintfArgs = sprintfCall.argument.filter(arg => arg.order >= 3).l
      
      // Check if any of these arguments reference tainted variables
      sprintfArgs.exists { arg =>
        val argCode = arg.code
        // Extract variable name from argument code
        val argVarOpt = extractVariableName(argCode)
        
        argVarOpt match {
          case Some(argVar) => taintedVars.contains(argVar)
          case None => false
        }
      }
    }
    
    /**
      * Extracts only the tainted parameters from sprintf call.
      * Returns a list of parameter names/codes that are from user input.
      */
    private def getTaintedSprintfParameters(method: io.shiftleft.codepropertygraph.generated.nodes.Method, sprintfCall: io.shiftleft.codepropertygraph.generated.nodes.Call): List[String] = {
      // Build set of tainted variables (user input sources)
      val taintedVars = buildTaintedVariables(method)
      
      // Get sprintf arguments from position 3 onwards (format string is at position 2)
      // Arguments start from 1, so 3+ means the format arguments/values for sprintf
      val sprintfArgs = sprintfCall.argument.filter(arg => arg.order >= 3).l
      
      // Filter and collect only the tainted arguments
      sprintfArgs.flatMap { arg =>
        val argCode = arg.code
        // Extract variable name from argument code
        val argVarOpt = extractVariableName(argCode)
        
        argVarOpt match {
          case Some(argVar) if taintedVars.contains(argVar) => Some(argCode)
          case _ => None
        }
      }
    }
    
    /**
      * Builds a set of tainted variables (user input sources) in the method.
      * 
      * Tainted variables include:
      * 1. Variables assigned from sub_422EB8 calls: v19 = sub_422EB8(a1, "userEmail")
      * 2. Variables derived through sub_406BB8: v20 = sub_406BB8(v19)
      */
    private def buildTaintedVariables(method: io.shiftleft.codepropertygraph.generated.nodes.Method): Set[String] = {
      // Find all sub_422EB8 call results - these are direct user input sources
      val directUserInputVars = method.ast.isCall.name("sub_422EB8").l.flatMap { call =>
        // Find assignment where this call's result is stored
        // Look for patterns like: v19 = sub_422EB8(...)
        findAssignmentTarget(method, call)
      }.toSet
      
      // Find variables derived through sub_406BB8 from user input variables
      val derivedVars = method.ast.isCall.name("sub_406BB8").l.flatMap { call =>
        // Check if the argument to sub_406BB8 is a tainted variable
        val argVars = call.argument.code.l.flatMap(extractVariableName)
        if (argVars.exists(directUserInputVars.contains)) {
          // This sub_406BB8 call takes tainted input, so its result is also tainted
          findAssignmentTarget(method, call)
        } else {
          List.empty
        }
      }.toSet
      
      directUserInputVars ++ derivedVars
    }
    
    /**
      * Finds the variable that receives the result of a function call.
      * Looks for assignment patterns like: varName = functionCall(...)
      */
    private def findAssignmentTarget(method: io.shiftleft.codepropertygraph.generated.nodes.Method, call: io.shiftleft.codepropertygraph.generated.nodes.Call): Option[String] = {
      // Get the line number of the call
      val callLine = call.lineNumber.getOrElse(-1)
      
      // Look for assignment operations at the same line
      method.ast.isCall.name("<operator>.assignment").filter(_.lineNumber.getOrElse(-2) == callLine).headOption.flatMap { assignment =>
        // The first argument of assignment is typically the target (LHS)
        assignment.argument.order(1).headOption.flatMap { target =>
          extractVariableName(target.code)
        }
      }.orElse {
        // Alternative: try to find from the code pattern directly
        // Look for patterns like "v19 = sub_422EB8(...)" in the call code
        val callCode = call.code
        val assignPattern = """(\w+)\s*=\s*""".r
        
        // Search in surrounding context for assignment
        method.ast.isCall.filter { c =>
          c.lineNumber.getOrElse(-2) == callLine && c.code.contains(call.name)
        }.flatMap { c =>
          assignPattern.findFirstMatchIn(c.code).map(_.group(1))
        }.headOption
      }
    }
    
    /**
      * Checks if there's security validation before the system call.
      * Returns true if validation is found, false otherwise.
      * 
      * Security validations might include:
      * - Input sanitization functions
      * - String validation/filtering
      * - Command whitelist checks
      */
    private def checkSecurityValidation(method: io.shiftleft.codepropertygraph.generated.nodes.Method, systemCall: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
      val systemLine = systemCall.lineNumber.getOrElse(Int.MaxValue)
      
      // List of security-related function names that might indicate sanitization
      val sanitizationFuncs = Set(
        "sanitize",
        "validate",
        "filter",
        "escape",
        "verify",
        "whitelist",
        "blacklist"
      )
      
      // Check if any sanitization function is called before the system call
      val hasSanitization = method.ast.isCall
        .filter(call => call.lineNumber.exists(_ < systemLine))
        .exists { call =>
          val callName = call.name.toLowerCase
          // Use exact match or starts with pattern to avoid false positives
          sanitizationFuncs.exists(func => 
            callName == func || callName.startsWith(s"${func}_") || callName.endsWith(s"_${func}")
          ) ||
          // Also check for strstr/strchr which are commonly used for validation
          (callName == "strstr" || callName == "strchr")
        }
      
      hasSanitization
    }
    /**
      * Detects field access without null check vulnerabilities (a->b pattern).
      * Returns a list of tuples: (methodName, lineNumber, objectName, fieldAccessCode)
      */
    private def detectFieldAccessWithoutNullCheck(tracedMethods: List[io.shiftleft.codepropertygraph.generated.nodes.Method]): List[(String, Int, String, String)] = {
      val tracedMethodsfilter = tracedMethods.filterNot(_.name == "<global>")
      val allVulnerabilities = scala.collection.mutable.ListBuffer[(String, Int, String, String)]()
      
      for (method <- tracedMethodsfilter) {
        val methodName = method.name
        
        // Function parameters are the caller's responsibility to validate before passing.
        // Flagging every `param->field` without a local null check creates massive noise
        // in decompiled code where no defensive checks exist inside the callee.
        val paramNames = method.parameter.name.toSet
        
        // Get all field accesses in this method (a->b pattern), sorted by line for first-occurrence reporting
        val fieldAccesses = method.fieldAccess.l.sortBy(_.lineNumber.getOrElse(0))
        
        if (fieldAccesses.nonEmpty) {
          // Eagerly compute AST nodes once per method (avoid repeated calls)
          val astNodes = method.ast.l
          
          // Track already-reported pointer names to deduplicate: report only the first
          // unguarded access per pointer per method (avoids flooding with dozens of hits
          // for the same un-checked pointer used many times in one function).
          val reportedPointers = scala.collection.mutable.Set[String]()
          
          // Process each field access
          for (fa <- fieldAccesses) {
            val lineNo = fa.lineNumber.getOrElse(0)
            val fieldAccessCode = fa.code
            
            // Extract object name from field access code (a->b, extract "a")
            // Handle various patterns: a->b, ptr->field, (*ptr)->field, etc.
            val objectNameOpt = if (fieldAccessCode.contains("->")) {
              val parts = fieldAccessCode.split("->")
              if (parts.length >= 1) {
                val objectPart = parts(0).trim
                // Clean up the object name: remove *, &, casts, parentheses
                val cleaned = objectPart
                  .replaceAll("\\([^)]*\\)", "") // Remove casts like (Type*)
                  .replaceAll("[*&()]", "") // Remove *, &, ()
                  .trim
                
                // Extract variable name (first identifier)
                val varPattern = "([a-zA-Z_][a-zA-Z0-9_]*).*".r
                cleaned match {
                  case varPattern(varName) => Some(varName)
                  case _ => None
                }
              } else {
                None
              }
            } else {
              None
            }
            
            objectNameOpt.foreach { objectName =>
              // Skip: already reported, function parameters (caller's responsibility),
              // and C++ `this` pointer (always non-null).
              if (objectName.nonEmpty && lineNo > 0 &&
                  !reportedPointers.contains(objectName) &&
                  !paramNames.contains(objectName) &&
                  objectName != "this") {
                
                // Include nodes up to AND INCLUDING the current line so that same-line
                // guards are recognized (e.g. `if (ptr && ptr->field)` or ternary
                // `ptr ? ptr->field : default`).
                val guardNodes = astNodes.filter { node =>
                  node.lineNumber.getOrElse(0) <= lineNo
                }
                
                // Check for null guards using multiple patterns
                val hasNullCheck = guardNodes.exists { node =>
                  val code = node.code
                  val n = objectName
                  
                  // 1. if-based null checks
                  val ifCheck = code.contains("if") && (
                    code.contains(s"if($n)") ||
                    code.contains(s"if(!$n)") ||
                    code.contains(s"if ($n)") ||
                    code.contains(s"if (!$n)") ||
                    code.contains(s"if($n ==") ||
                    code.contains(s"if($n !=") ||
                    code.contains(s"if ($n ==") ||
                    code.contains(s"if ($n !=") ||
                    code.contains(s"if($n==") ||
                    code.contains(s"if($n!=") ||
                    code.contains(s"== $n)") ||
                    code.contains(s"!= $n)")
                  )
                  
                  // 2. Logical-AND short-circuit: `ptr && ptr->field` — ptr is non-null
                  //    when the right side is evaluated (no opening parenthesis required)
                  val andCheck = code.contains(s"$n &&")
                  
                  // 3. Ternary guard: `ptr ? ptr->field : default`
                  val ternaryCheck = code.contains(s"$n ?") || code.contains(s"$n?")
                  
                  // 4. while loop condition null checks (ptr != NULL or bare ptr — both guarantee
                  //    non-null inside the loop body; while(ptr == NULL) does NOT guard access)
                  val whileCheck = code.contains("while") && (
                    code.contains(s"while($n)") ||
                    code.contains(s"while ($n)") ||
                    code.contains(s"while($n !=") ||
                    code.contains(s"while ($n !=")
                  )
                  
                  // 5. assert / BUG_ON / WARN_ON / kernel-style macro null checks
                  val assertCheck = (
                    code.contains(s"assert($n)") ||
                    code.contains(s"assert ($n)") ||
                    code.contains(s"assert($n !=") ||
                    code.contains(s"assert ($n !=") ||
                    code.contains(s"BUG_ON(!$n)") ||
                    code.contains(s"BUG_ON(! $n)") ||
                    code.contains(s"WARN_ON(!$n)") ||
                    code.contains(s"WARN_ON(! $n)")
                  )
                  
                  // 6. Address-of assignment guarantees non-null (ptr = &var)
                  val addressOfAssign = (
                    code.contains(s"$n = &") ||
                    code.contains(s"$n=&")
                  )
                  
                  // 7. Direct comparison with 0 / NULL / nullptr in any expression context.
                  //    IDA Pro decompiles 64-bit null comparisons as "!= 0LL", which the
                  //    if-based patterns above don't catch when the `if` keyword is on a
                  //    different AST node than the condition text.
                  val zeroNullCheck = (
                    code.contains(s"$n != 0") ||
                    code.contains(s"$n != NULL") ||
                    code.contains(s"$n != nullptr") ||
                    code.contains(s"0 != $n") ||
                    code.contains(s"NULL != $n") ||
                    code.contains(s"nullptr != $n")
                  )
                  
                  // 8. Assignment-expression null check: ($n = expr) != 0/NULL.
                  //    IDA frequently emits: if ( (v47 = v39->nodesetval) != 0LL && ... )
                  //    The CPG condition node contains "($n =" and "!= 0" in the same code string.
                  val assignCompareCheck = (
                    code.contains(s"($n =") &&
                    (code.contains("!= 0") || code.contains("!= NULL") || code.contains("!= nullptr"))
                  )
                  
                  // 9. Variable is the right-hand or middle operand of a short-circuit && chain.
                  //    e.g. `something && n)` or `something && n &&` — n is tested for truthiness.
                  val andRightCheck = (
                    code.contains(s"&& $n)") ||
                    code.contains(s"&& $n &&") ||
                    code.contains(s"&&$n)") ||
                    code.contains(s"&&$n &&")
                  )
                  
                  // 10. C++ new-expression: `n = new Type(...)` never returns null (throws on OOM).
                  val newAllocationCheck = (
                    code.contains(s"$n = new ") ||
                    code.contains(s"$n=new ")
                  )
                  
                  ifCheck || andCheck || ternaryCheck || whileCheck || assertCheck ||
                  addressOfAssign || zeroNullCheck || assignCompareCheck ||
                  andRightCheck || newAllocationCheck
                }
                
                // If no NULL check found, record the first unguarded access for this pointer
                if (!hasNullCheck) {
                  reportedPointers += objectName
                  allVulnerabilities += ((methodName, lineNo, objectName, fieldAccessCode))
                }
              }
            }
          }
        }
      }
      
      allVulnerabilities.toList
    }
    
    /**
      * Writes vulnerability results to a file in a categorized format.
      */
    private def writeVulnerabilitiesToFile(vulnerabilities: Map[String, List[String]], outputPath: String): Unit = {
      Try {
        val writer = new PrintWriter(outputPath)
        try {
          writer.println("=" * 80)
          writer.println("Vulnerability Detection Report")
          writer.println("=" * 80)
          writer.println()
          
          if (vulnerabilities.isEmpty) {
            writer.println("No vulnerabilities detected.")
          } else {
            val totalCount = vulnerabilities.values.map(_.size).sum
            writer.println(s"Total vulnerabilities found: $totalCount")
            writer.println()
            
            vulnerabilities.foreach { case (category, vulnList) =>
              writer.println("-" * 80)
              writer.println(s"Category: $category")
              writer.println(s"Count: ${vulnList.size}")
              writer.println("-" * 80)
              
              vulnList.zipWithIndex.foreach { case (vuln, idx) =>
                writer.println(s"${idx + 1}. $vuln")
              }
              writer.println()
            }
          }
          
          writer.println("=" * 80)
          writer.println("End of Report")
          writer.println("=" * 80)
        } finally {
          writer.close()
        }
      } match {
        case Success(_) =>
          println(s"[+] Vulnerability report written to: $outputPath")
        case Failure(e) =>
          println(s"[!] Failed to write vulnerability report: ${e.getMessage}")
      }
    }
    
    /**
      * Detects vulnerable memcpy patterns in a given method.
      * Looks for memcpy calls in the method's AST that match the vulnerability criteria:
      * 1. Destination address is in "ptr + offset" form
      * 2. There is a subtraction operation before the memcpy
      * 3. There is only compound comparison (e.g., a+b > c) without simple comparison (e.g., b < c)
      */
    private def findVulnerableMemcpy(method: io.shiftleft.codepropertygraph.generated.nodes.Method): List[io.shiftleft.codepropertygraph.generated.nodes.Call] = {
      val arithmeticOperators = Set("+", "-", "*", "/", "%")
      method.ast.isCall.name("memcpy").filter { memcpyCall =>
        try {
          // Get the first argument (destination address)
          val destArg = memcpyCall.argument.order(1).headOption
          val destCode = destArg.map(_.code).getOrElse("")
          
          // Condition 1: Destination address contains addition (ptr + offset form)
          val hasAddition = destCode.contains("+")
          
          if (!hasAddition) {
            false
          } else {
            // Get parent block for context
            val parentBlockOpt = memcpyCall.astParent
            
            parentBlockOpt.exists { parentBlock =>
              // Condition 2: Check for subtraction operation before memcpy
              val memcpyLineNum = memcpyCall.lineNumber.getOrElse(Int.MaxValue)
              val hasSubtraction = parentBlock.ast.isCall
                .name("<operator>.subtraction")
                .exists { sub =>
                  sub.lineNumber.getOrElse(Int.MaxValue) < memcpyLineNum
                }
              
              if (!hasSubtraction) {
                false
              } else {
                // Condition 3: Check for comparison operations
                val comparisonCalls = parentBlock.ast.isCall
                  .filter { 
                    call => comparisonOperators.contains(call.name) && call.lineNumber.getOrElse(Int.MaxValue) < memcpyLineNum  // 限制行号
                  }.l
                
                val simpleComparisons = comparisonCalls.filter { call =>
                  // A simple comparison has no addition in its arguments
                  val args = call.argument.code.l
                  args.nonEmpty && !args.exists{ arg =>
                    arithmeticOperators.exists(op => arg.contains(op))
                  }
                }.l
                
                simpleComparisons.isEmpty
              }
            }
          }
        } catch {
          case e: Exception =>
            println(s"[!] Error analyzing memcpy call: ${e.getMessage}")
            false
        }
      }.l
    }
    
    /**
      * Detects vulnerable copy function patterns in a given method.
      * Looks for strncpy, memcpy, memmove calls that match the vulnerability criteria:
      * 1. Destination is a limited-size local variable (not dynamically allocated)
      * 2. Source is user-controllable (parameter or derived from parameter)
      * 3. Size parameter is related to source (e.g., strlen(source))
      * Note: strcpy is excluded as it doesn't have a size parameter
      */
    private def findVulnerablewithcpy(method: io.shiftleft.codepropertygraph.generated.nodes.Method): List[io.shiftleft.codepropertygraph.generated.nodes.Call] = {

      val copyFunctions = List("strncpy", "memcpy", "memmove")

      def baseVar(code: String): Option[String] = {
        val i = code.indexOf("->")
        if (i > 0) Some(code.substring(0, i).trim)
        else {
          val j = code.indexOf(".")
          if (j > 0) Some(code.substring(0, j).trim)
          else None
        }
      }

      def stripAddr(code: String): String =
        code.replaceAll("""\s*\(char\s*\*\)\s*""", "")
            .replaceAll("""\s*&\s*""", "")
            .trim

      def isFieldOfParam(code: String): Boolean = {
        val params = method.parameter.name.l
        params.exists(p => code.contains(p + "->") || code.contains(p + "."))
      }

      def isLimitedLocal(varName: String): Boolean =
        method.local.name(varName).exists(l => !l.typeFullName.endsWith("*"))

      def sizeIsParamDerived(sizeVar: String, copyLine: Int): Boolean = {
        if (sizeVar.isEmpty) false
        else {
          val assigns = method.ast.isCall
            .code(s"$sizeVar.*=.*")
            .lineNumberLt(copyLine)
            .l
          assigns.exists(a => isFieldOfParam(a.code))
        }
      }

      def sizeFromStrlen(sizeVar: String, srcVar: String, copyLine: Int): Boolean = {
        if (sizeVar.isEmpty || srcVar.isEmpty) false
        else {
          val assigns = method.ast.isCall
            .code(s"$sizeVar.*=.*")
            .lineNumberLt(copyLine)
            .l
          assigns.exists(a => a.code.contains("strlen") && a.code.contains(srcVar))
        }
      }

      copyFunctions.flatMap { funcName =>
        method.ast.isCall.name(funcName).filter { copyCall =>
          try {
            val copyLineNum = copyCall.lineNumber.getOrElse(Int.MaxValue)

            val destArg = copyCall.argument.order(1).headOption
            val srcArg  = copyCall.argument.order(2).headOption
            val sizeArg = copyCall.argument.order(3).headOption

            if (sizeArg.exists(_.isLiteral)) {
              false
            } else {
              val destCode = destArg.map(_.code).getOrElse("")
              val srcCode  = srcArg.map(_.code).getOrElse("")
              val sizeCode = sizeArg.map(_.code).getOrElse("")

              val srcBase  = baseVar(srcCode)
              val sizeBase = baseVar(sizeCode)

              val destNameOpt =
                destArg.collect { case id: io.shiftleft.codepropertygraph.generated.nodes.Identifier => id.name }

              val srcNameOpt =
                srcArg.collect { case id: io.shiftleft.codepropertygraph.generated.nodes.Identifier => id.name }

              val sizeNameOpt =
                sizeArg.collect { case id: io.shiftleft.codepropertygraph.generated.nodes.Identifier => id.name }

              val destAddrName = stripAddr(destCode)

              val destIsLimitedLocal =
                destNameOpt.exists(isLimitedLocal) || isLimitedLocal(destAddrName)

              val srcIsUserControlled = {
                val params = method.parameter.name.l
                srcBase.exists(params.contains) ||
                isFieldOfParam(srcCode) ||
                srcNameOpt.exists { sv =>
                  val assigns = method.ast.isCall
                    .code(s"$sv.*=.*")
                    .lineNumberLt(copyLineNum)
                    .l
                  assigns.exists(a => a.argument.exists(arg =>
                    params.exists(p => arg.code.contains(p))
                  ))
                }
              }

              val sizeRelatedToSrc = {
                val sameBaseParam =
                  (srcBase, sizeBase) match {
                    case (Some(b1), Some(b2)) if b1 == b2 =>
                      isFieldOfParam(srcCode) && isFieldOfParam(sizeCode)
                    case _ => false
                  }

                val byAssignment = srcBase.exists { sv =>
                  sizeBase.exists { szv =>
                    val sizeAssignments = method.ast.isCall
                      .code(s"$szv.*=.*")
                      .lineNumberLt(copyLineNum)
                      .l
                    sizeAssignments.exists(_.code.contains(sv))
                  }
                }

                val sizeFromParam = sizeNameOpt.exists(sz => sizeIsParamDerived(sz, copyLineNum))
                val sizeFromStr = (srcNameOpt, sizeNameOpt) match {
                  case (Some(sv), Some(sz)) => sizeFromStrlen(sz, sv, copyLineNum)
                  case _ => false
                }

                sameBaseParam || byAssignment || sizeFromParam || sizeFromStr
              }

              val isVulnerable =
                destIsLimitedLocal && srcIsUserControlled && sizeRelatedToSrc

              // if (isVulnerable) {
              //   println(s"[!] Vulnerable $funcName found:")
              //   println(s"    Destination: $destCode (limited local: $destIsLimitedLocal)")
              //   println(s"    Source: $srcCode (user-controlled: $srcIsUserControlled)")
              //   println(s"    Size: $sizeCode (related to source: $sizeRelatedToSrc)")
              // }

              isVulnerable
            }
          } catch {
            case e: Exception =>
              println(s"[!] Error analyzing $funcName call: ${e.getMessage}")
              false
          }
        }.l
      }
    }
    
    /**
      * Extracts the variable name from code expressions.
      * Examples:
      * "(char *)&v26" -> Some("v26")
      * "v7" -> Some("v7")
      * "v8" -> Some("v8")
      */
    private def extractVariableName(code: String): Option[String] = {
      // Remove casts, address-of operators, and other noise
      val cleaned = code
        .replaceAll("\\([^)]*\\)\\s*", "") // Remove casts like (char *)
        .replaceAll("&", "") // Remove address-of operator
        .trim
      
      // Extract the first identifier (variable name)
      val varPattern = "([a-zA-Z_][a-zA-Z0-9_]*)".r
      varPattern.findFirstIn(cleaned)
    }
    
    /**
      * Detects use-after-free vulnerabilities in traced methods.
      * Returns a list of tuples: (fileName, funcName, ptrAssignLine, ptrAssignCode, targetVar, freeLine, freeCode, useLine, useCode, freedArg)
      */
    private def detectUseAfterFree(tracedMethods: List[io.shiftleft.codepropertygraph.generated.nodes.Method]): List[(String, String, Int, String, String, Int, String, Int, String, String)] = {
      val realTracedMethods = tracedMethods.filterNot(_.name == "<global>")
      val results = realTracedMethods.flatMap { method =>
        method.ast.isCall.name(".*[Ff][Rr][Ee][Ee].*").l.flatMap { f =>
          val freeLine = f.lineNumber.getOrElse(0)
          val freeCode = f.code
          val freeArg = f.argument.order(1).headOption.map(_.code).getOrElse("")
          val funcName = method.name
          val fileName = f.file.name.l.headOption.getOrElse("unknown")
          
          // Skip if no free argument
          if (freeArg.isEmpty) {
            Seq()
          } else {
            // Collect all assignments before the free call once
            val allAssignments = method.ast.isCall
              .name("<operator>.assignment")
              .l
              .filter(a => a.lineNumber.getOrElse(Int.MaxValue) < freeLine)

            // Resolve simple (non-pointer) alias chain to find root variable
            val aliasMap = scala.collection.mutable.Map[String, String]()
            allAssignments.foreach { assign =>
              val lhs = assign.argument.order(1).headOption.map(_.code).getOrElse("")
              val rhs = assign.argument.order(2).headOption.map(_.code).getOrElse("")
              if (!rhs.contains("*") && !rhs.contains("->")) {
                aliasMap(lhs) = rhs
              }
            }
            def resolveAlias(v: String, visited: Set[String] = Set.empty): String = {
              if (visited.contains(v)) v
              else if (aliasMap.contains(v)) resolveAlias(aliasMap(v), visited + v)
              else v
            }
            val rootVar = resolveAlias(freeArg)

            // Build a transitive set of variables derived from freeArg.
            // This handles chains like: v40=v39; v47=v39->nodesetval; v41=*v47->nodeTab
            // so that v41's pointer source is recognised as related to v40.
            val relatedVars = scala.collection.mutable.Set[String](freeArg, rootVar)
            var changed = true
            while (changed) {
              changed = false
              allAssignments.foreach { assign =>
                val lhs = assign.argument.order(1).headOption.map(_.code).getOrElse("")
                val rhs = assign.argument.order(2).headOption.map(_.code).getOrElse("")
                if (lhs.nonEmpty && !relatedVars.contains(lhs) && relatedVars.exists(v => rhs.contains(v))) {
                  relatedVars.add(lhs)
                  changed = true
                }
              }
            }
            
            // Find pointer assignments (containing * and ->)
            allAssignments
              .filter(a => a.code.contains("*") && a.code.contains("->"))
              .flatMap { ptrAssign =>
                val targetVar = ptrAssign.argument.order(1).headOption.map(_.code).getOrElse("")
                val ptrAssignLine = ptrAssign.lineNumber.getOrElse(0)
                val ptrSource = ptrAssign.argument.order(2).headOption.map(_.code).getOrElse("")
                
                // Related if the pointer source derives (transitively) from the freed variable
                val isRelated = relatedVars.exists(v => ptrSource.contains(v))
                
                if (isRelated && targetVar.nonEmpty) {
                  // Find uses of targetVar after free (with word boundary matching).
                  // Skip uses that are reassignments to targetVar — those are re-inits, not UAF.
                  method.ast.isCall.l
                    .filter(c => c.lineNumber.getOrElse(0) > freeLine)
                    .filter { c =>
                      // Use word boundary matching to avoid partial matches
                      val pattern = s"\\b${java.util.regex.Pattern.quote(targetVar)}\\b".r
                      pattern.findFirstIn(c.code).isDefined
                    }
                    .filter { c =>
                      // Skip reassignments: `targetVar = ...` after free is a re-initialisation
                      !(c.name == "<operator>.assignment" &&
                        c.argument.order(1).headOption.map(_.code).contains(targetVar))
                    }
                    .map { use =>
                      (
                        fileName,
                        funcName,
                        ptrAssignLine,
                        ptrAssign.code,
                        targetVar,
                        freeLine,
                        freeCode,
                        use.lineNumber.getOrElse(0),
                        use.code,
                        freeArg
                      )
                    }
                } else {
                  Seq()
                }
              }
          }
        }
      }

      // Deduplication: per (file, func, var_, freeLine) keep only the earliest use site
      val deduplicated = results
        .distinct
        .groupBy { case (file, func, _, _, var_, freeLine, _, _, _, _) =>
          (file, func, var_, freeLine)
        }
        .map { case (_, group) => group.minBy(_._8) }
        .toSeq

      // Sort by file, function, freeLine, ptrLine, useLine
      val sorted = deduplicated.sortBy { case (file, func, ptrLine, _, _, freeLine, _, useLine, _, _) =>
        (file, func, freeLine, ptrLine, useLine)
      }

      sorted.toList
    }
    
    /**
      * Detects off-by-one vulnerabilities in traced methods.
      * Returns a list of tuples: (methodName, checkFuncName, checkLine, checkCode, writeFuncName, writeLine, writeCode)
      */
    private def detectOffByOne(tracedMethods: List[io.shiftleft.codepropertygraph.generated.nodes.Method]): List[(String, String, Int, String, String, Int, String)] = {
      val tracedMethodsfilter = tracedMethods.filterNot(_.name == "<global>")
      // Dangerous functions that can cause off-by-one errors
      val dangerousFunctions = Set(
        "strcat", "strcpy", "sprintf", "vsprintf",
        "gets", "scanf", "memcpy", "memmove"
      )
      
      // Regex pattern to match manual null terminator writes: *ptr = 0
      // Matches patterns like: *dcptr = 0, *result = 0LL, etc.
      val manualTerminatorPattern = ".*\\*\\s*[A-Za-z_][A-Za-z0-9_\\->\\*\\[\\]]*\\s*=\\s*0.*"
      
      /**
        * Check if a method looks like a boundary check function using heuristics:
        * - Has loops (WHILE/FOR) or comparisons (>, <)
        * - Has memory allocation (realloc, malloc, calloc) or has parameters
        */
      def looksLikeCheckFunction(method: io.shiftleft.codepropertygraph.generated.nodes.Method): Boolean = {
        val hasLoop = method.ast.isControlStructure
          .controlStructureType("WHILE|FOR")
          .nonEmpty
        
        val hasComparison = method.ast.isCall
          .name("<operator>.greaterThan", "<operator>.lessThan")
          .nonEmpty
        
        val hasAlloc = method.ast.isCall
          .name("realloc", "malloc", "calloc")
          .nonEmpty
        
        (hasLoop || hasComparison) && (hasAlloc || method.parameter.size > 0)
      }
      
      // First, find all methods that look like boundary check functions
      val checkFunctionNames = tracedMethodsfilter.filter(looksLikeCheckFunction).map(_.name).toSet
      
      val results = tracedMethodsfilter.flatMap { m =>
        // Find all calls to boundary check functions
        val checkCalls = m.ast.isCall
          .filter { call =>
            checkFunctionNames.contains(call.name)
          }
          .l
        
        checkCalls.flatMap { checkCall =>
          val checkLine = checkCall.lineNumber.getOrElse(Int.MinValue)
          val checkCode = checkCall.code
          val checkName = checkCall.name
          
          // Find library function writes after the check
          val libWrites = m.ast.isCall
            .filter(call => dangerousFunctions.contains(call.name))
            .filter(_.lineNumber.exists(_ > checkLine))
            .map { dangerousCall =>
              (m.name, checkName, checkLine, checkCode, dangerousCall.name, 
               dangerousCall.lineNumber.getOrElse(Int.MinValue), dangerousCall.code)
            }
            .l
          
          // Find manual terminator writes after the check (*ptr = 0)
          val manualWrites = m.ast.isCall
            .filter { call =>
              call.code.matches(manualTerminatorPattern)
            }
            .filter(_.lineNumber.exists(_ > checkLine))
            .map { writeCall =>
              (m.name, checkName, checkLine, checkCode, "manual_terminator", 
               writeCall.lineNumber.getOrElse(Int.MinValue), writeCall.code)
            }
            .l
          
          libWrites ++ manualWrites
        }
      }
      
      // if (results.nonEmpty) {
      //   println(s"[!] Found ${results.size} off-by-one vulnerabilities")
      //   results.foreach { case (methodName, checkFunc, checkLine, checkCode, writeFunc, writeLine, writeCode) =>
      //     println(s"    Method: $methodName")
      //     println(s"    Check: $checkCode (line $checkLine)")
      //     println(s"    Write: $writeCode (line $writeLine)")
      //   }
      // } else {
      //   println("[+] No off-by-one vulnerabilities detected")
      // }
      
      results
    }
    
    /**
      * Detects integer overflow vulnerabilities in traced methods.
      * Returns a list of tuples: (methodName, lineNumber, code)
      */
    private def detectIntegerOverflow(tracedMethods: List[io.shiftleft.codepropertygraph.generated.nodes.Method]): List[(String, Int, String)] = {
      val tracedMethodsfilter = tracedMethods.filterNot(_.name == "<global>")
      
      // 1. Find all suspicious assignments
      val suspiciousAssignments = tracedMethodsfilter.flatMap { method =>
        method.ast.isCall.name("<operator>.assignment").filter { assignment =>
          // Check if left side is an overflow-prone integer type identifier
          val leftSideIsOverflowProne = assignment.argument.order(1).headOption.exists { arg =>
            arg.isIdentifier && method.local.name(arg.code).exists { local =>
              overflowProneTypes.contains(local.typeFullName)
            }
          }
          
          // Check if right side contains multiplication or shift left
          val rightSideHasRiskyOp = assignment.argument.order(2).headOption.exists { arg =>
            arg.ast.isCall.name("<operator>.multiplication", "<operator>.shiftLeft").nonEmpty
          }
          
          leftSideIsOverflowProne && rightSideHasRiskyOp
        }.map(a => (method, a))
      }
      
      // 2. Filter out assignments that have overflow checks
      val vulnerabilities = suspiciousAssignments.filterNot { case (method, assignment) =>
        hasOverflowCheck(method, assignment)
      }
      
      // 3. Format results
      val results = vulnerabilities.map { case (method, assignment) =>
        val methodName = method.name
        val lineNumber = assignment.lineNumber.getOrElse(-1)
        val code = assignment.code
        (methodName, lineNumber, code)
      }
      
      results.distinct
    }
    
    /**
      * Checks if an assignment has overflow protection.
      * Returns true if overflow checks are detected.
      */
    private def hasOverflowCheck(method: io.shiftleft.codepropertygraph.generated.nodes.Method, 
                                  assignment: io.shiftleft.codepropertygraph.generated.nodes.Call): Boolean = {
      val assignmentLine = assignment.lineNumber.getOrElse(0)
      val targetVar = assignment.argument.order(1).code.headOption.getOrElse("")
      
      // Check for pre-check (IF statement before assignment)
      val hasPreCheck = method.ast.isControlStructure
        .controlStructureType("IF")
        .filter(_.lineNumber.exists(_ < assignmentLine))
        .exists { ifStmt =>
          val condCode = ifStmt.condition.code.l.mkString(" ")
          // Common overflow check patterns
          condCode.matches(".*>(.*MAX|.*LIMIT).*") ||           // a * b > SIZE_MAX
          condCode.matches(".*/.*<.*") ||                        // a > SIZE_MAX / b
          condCode.matches(".*[Oo]verflow.*") ||              // xxxoverflowxxx
          condCode.matches(".*[Cc]hecked.*") ||                    // checked_mul
          condCode.matches(".*[Ss]afe.*")                          // safe_mul
        }
      
      // Check for post-check (IF statement after assignment checking result)
      val hasPostCheck = method.ast.isControlStructure
        .controlStructureType("IF")
        .filter(_.lineNumber.exists(_ > assignmentLine))
        .exists { ifStmt =>
          val condCode = ifStmt.condition.code.l.mkString(" ")
          condCode.contains(targetVar) && (
            condCode.matches(".*==\\s*0.*") ||              // size == 0
            condCode.matches(".*<.*") ||                    // size < expected
            condCode.matches(".*>.*MAX.*") ||               // size > MAX
            condCode.matches(".*[Oo]verflow.*")          // overflow check
          )
        }
      
      // Check for safe wrapper functions
      val useSafeWrapper = assignment.argument.order(2).headOption.exists { arg =>
        arg.ast.isCall.name
          .exists(name => 
            name.matches(".*([Cc]hecked|[Ss]afe|[Ss]ecure).*([Mm]ul|[Mm]ultiply|[Aa]dd|[Ss]hift).*")
          )
      }
      
      hasPreCheck || hasPostCheck || useSafeWrapper
    }
    
    /**
      * Detects integer overflow vulnerabilities in realloc operations.
      * Specifically targets cases where size calculations involve arithmetic operations
      * that could overflow before being passed to realloc-like functions.
      * 
      * Example vulnerable pattern:
      *   v58 = 2 * (v43[9] - v43[8]);
      *   v59 = expat_realloc(v27, v43[8], v58, 3507);
      * 
      * Returns a list of tuples: (methodName, reallocLine, reallocCode, assignLine, assignCode)
      */
    private def detectReallocIntegerOverflow(tracedMethods: List[io.shiftleft.codepropertygraph.generated.nodes.Method]): List[(String, Int, String, Int, String)] = {
      val tracedMethodsFilter = tracedMethods.filterNot(_.name == "<global>")
      
      tracedMethodsFilter.flatMap { method =>
        // Find all realloc-like function calls
        val reallocCalls = method.ast.isCall.name(".*realloc.*").l
        
        reallocCalls.flatMap { reallocCall =>
          val reallocLine = reallocCall.lineNumber.getOrElse(Int.MaxValue)
          val reallocCode = reallocCall.code
          
          // Get identifiers used in the size argument (typically argument 3)
          // For functions like realloc(ptr, size) or expat_realloc(ctx, ptr, size, tag)
          val sizeArguments = reallocCall.argument.order(2, 3).l
          val sizeIdentifiers = sizeArguments.flatMap(_.ast.isIdentifier.name.l).toSet
          
          if (sizeIdentifiers.isEmpty) {
            Iterator.empty
          } else {
            // Find assignments to these identifiers in the same method
            val suspiciousAssignments = method.ast.isCall.name("<operator>.assignment").filter { assignment =>
              val assignLine = assignment.lineNumber.getOrElse(0)
              
              // Assignment should be before the realloc call
              if (assignLine >= reallocLine) {
                false
              } else {
                // Check if the assignment target is one of the identifiers used in realloc size
                val assignTarget = assignment.argument.order(1).code.headOption.getOrElse("")
                val isTargetMatch = sizeIdentifiers.contains(assignTarget)
                
                // Check if the right side contains risky arithmetic operations
                val hasRiskyArithmetic = assignment.argument.order(2).headOption.exists { arg =>
                  val rightSideCode = arg.code
                  // Check for multiplication or shift operations
                  val hasMultOrShift = arg.ast.isCall.name("<operator>.multiplication", "<operator>.shiftLeft").nonEmpty
                  // Also check for explicit operators in code
                  val hasArithmeticOp = rightSideCode.contains("*") || rightSideCode.contains("<<")
                  hasMultOrShift || hasArithmeticOp
                }
                
                isTargetMatch && hasRiskyArithmetic
              }
            }.l
            
            // For each suspicious assignment, check if there's overflow protection
            suspiciousAssignments.filterNot { assignment =>
              hasReallocOverflowCheck(method, assignment, reallocCall)
            }.map { assignment =>
              val assignLine = assignment.lineNumber.getOrElse(-1)
              val assignCode = assignment.code
              (method.name, reallocLine, reallocCode, assignLine, assignCode)
            }
          }
        }
      }.distinct
    }
    
    /**
      * Checks if a realloc operation has overflow protection for its size calculation.
      * Returns true if overflow checks are detected.
      */
    private def hasReallocOverflowCheck(
      method: io.shiftleft.codepropertygraph.generated.nodes.Method,
      assignment: io.shiftleft.codepropertygraph.generated.nodes.Call,
      reallocCall: io.shiftleft.codepropertygraph.generated.nodes.Call
    ): Boolean = {
      val assignmentLine = assignment.lineNumber.getOrElse(0)
      val reallocLine = reallocCall.lineNumber.getOrElse(Int.MaxValue)
      val targetVar = assignment.argument.order(1).code.headOption.getOrElse("")
      
      // Check for overflow checks between assignment and realloc call
      val hasCheckBetween = method.ast.isControlStructure
        .controlStructureType("IF")
        .filter { ifStmt =>
          val ifLine = ifStmt.lineNumber.getOrElse(0)
          ifLine > assignmentLine && ifLine < reallocLine
        }
        .exists { ifStmt =>
          val condCode = ifStmt.condition.code.l.mkString(" ")
          // Check for common overflow check patterns
          (condCode.contains(targetVar) || condCode.matches(".*[Oo]verflow.*")) && (
            condCode.matches(".*>(.*MAX|.*LIMIT).*") ||    // size > SIZE_MAX
            condCode.matches(".*/.*<.*") ||                 // a > SIZE_MAX / b
            condCode.matches(".*==\\s*0.*") ||              // size == 0 (overflow wrapped)
            condCode.matches(".*<.*") ||                    // size < operand (overflow check)
            condCode.matches(".*[Cc]hecked.*") ||           // checked_mul
            condCode.matches(".*[Ss]afe.*")                 // safe_mul
          )
        }
      
      // Check if assignment uses safe wrapper functions
      val usesSafeWrapper = assignment.argument.order(2).headOption.exists { arg =>
        arg.ast.isCall.name
          .exists(name => 
            name.matches(".*([Cc]hecked|[Ss]afe|[Ss]ecure).*([Mm]ul|[Mm]ultiply|[Aa]dd|[Ss]hift).*")
          )
      }
      
      // Check if realloc result is checked for NULL/failure
      val hasResultCheck = method.ast.isControlStructure
        .controlStructureType("IF")
        .filter(_.lineNumber.exists(_ > reallocLine))
        .exists { ifStmt =>
          val condCode = ifStmt.condition.code.l.mkString(" ")
          val reallocTarget = if (reallocCall.code.contains("=")) {
            reallocCall.code.split("=", 2)(0).trim
          } else {
            ""
          }
          reallocTarget.nonEmpty && condCode.contains(reallocTarget) && (
            condCode.matches(".*==\\s*(NULL|0).*") ||
            condCode.matches(".*!=\\s*(NULL|0).*") ||
            condCode.matches(".*!.*")
          )
        }
      
      hasCheckBetween || usesSafeWrapper || hasResultCheck
    }
  }
}
